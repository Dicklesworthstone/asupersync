//! Real production mTLS service/client plus public symbol distribution and fetch.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
// An integration test is its own crate and does not inherit `src/lib.rs`'s
// `recursion_limit`. Proving `Send` for its async chains exceeds rustc's default
// depth, which the future-incompatible `recursion_depth_exceeding_limit` lint
// (rust-lang #159228) will turn into a hard error.
#![recursion_limit = "256"]

use asupersync::distributed::distribution::{DistributionConfig, DistributorTransport, SymbolDistributor};
use asupersync::distributed::symbol_service::{
    ChunkedSymbolService, RemoteSymbolTransport, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
    SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits, SymbolChunkedLimits, SymbolReplicaStore,
    SymbolStoreLimits, encode_symbol_batch, register_chunked_symbol_service, register_symbol_service,
};
use asupersync::distributed::EncodedState;
use asupersync::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use asupersync::remote::{
    NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteServiceWireLimits,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use asupersync::types::symbol::{ObjectParams, Symbol};
use asupersync::{Cx, types::Time};
use std::sync::Arc;
use std::time::Duration;

const CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("fixtures/tls/server.key");

fn limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 8192, max_symbols: 32, max_payload_bytes: 4096, max_decoded_bytes: 16384 }
}
fn tls(identity: bool) -> (TlsAcceptor, TlsConnector, CertificatePinSet) {
    let certificate = Certificate::from_pem(CERT).unwrap().remove(0);
    let chain = CertificateChain::from_pem(CERT).unwrap();
    let key = PrivateKey::from_pem(KEY).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
        .client_auth(ClientAuth::Required(roots)).build().unwrap();
    let mut connector = TlsConnectorBuilder::new().add_root_certificate(&certificate);
    if identity { connector = connector.identity(chain, key); }
    let mut pins = CertificatePinSet::new();
    pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    (acceptor, connector.build().unwrap(), pins)
}

struct DrainOnDrop(RemoteComputationServiceHandle);
impl Drop for DrainOnDrop {
    fn drop(&mut self) { let _ = self.0.begin_drain(); }
}

struct ClientJoin(Option<std::thread::JoinHandle<()>>);
impl Drop for ClientJoin {
    fn drop(&mut self) { if let Some(thread) = self.0.take() { let _ = thread.join(); } }
}

#[derive(Clone, Copy)]
enum Case { Roundtrip, WrongTarget, WrongSymbolKey, MissingClientIdentity, UnauthorizedPeer }

fn exercise(case: Case, workers: usize) {
    let receiver_key = if matches!(case, Case::WrongSymbolKey) { 43 } else { 42 };
    let store = Arc::new(SymbolReplicaStore::new(
        "replica-a", AuthKey::from_seed(receiver_key), limits(),
        SymbolStoreLimits { max_batches: 2, max_bytes: 16384, max_batches_per_peer: 1, max_bytes_per_peer: 8192 },
    ).unwrap());
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::clone(&store)).unwrap();
    let (acceptor, connector, pins) = tls(!matches!(case, Case::MissingClientIdentity));
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(NodeId::new("origin-a"), pins, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    let origin = if matches!(case, Case::UnauthorizedPeer) { "ungranted-origin" } else { "origin-a" };
    let hello = policy.hello_for(NodeId::new(origin));
    let server = RuntimeBuilder::current_thread().build().unwrap();
    let service = server.block_on(RemoteComputationService::bind(
        "127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_max_connections(Some(4))
            .with_drain_timeout(Duration::from_secs(3)),
    )).unwrap();
    let endpoint = service.local_addr().unwrap();
    let operator = service.handle();
    let client_operator = operator.clone();
    let retained = Arc::clone(&store);
    let mut client = ClientJoin(Some(std::thread::spawn(move || {
        // Even a client assertion failure asks the real listener to stop accepting.
        let _drain = DrainOnDrop(client_operator);
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async move {
            let cx = Cx::current().expect("native context");
            let client = RemoteComputationClient::new(endpoint, "localhost", connector,
                RemoteComputationClientConfig::new().with_max_attempts(1)
                    .with_connect_timeout(Duration::from_secs(2))
                    .with_attempt_timeout(Duration::from_secs(3)),
            ).unwrap();
            let replica = if matches!(case, Case::WrongTarget) { "wrong-replica" } else { "replica-a" };
            let transport = RemoteSymbolTransport::new(
                cx.clone(), hello, [(replica.to_owned(), client)], Arc::new(AuthKey::from_seed(42)), limits(),
            ).unwrap();
            let security = SecurityContext::new(AuthKey::from_seed(42));
            security.authorize_replica(replica, None).unwrap();
            let encoded = EncodedState {
                params: ObjectParams::new_for_test(17, 1024),
                symbols: (0..3).map(|esi| Symbol::new_for_test(17, 0, esi, b"actual replicated bytes")).collect(),
                source_count: 3, repair_count: 0, original_size: 69,
                encoded_at: Time::ZERO, layout_decision: Default::default(),
            };
            let signed: Vec<_> = encoded.symbols.iter().map(|s| security.sign_symbol(s)).collect();
            let key = encode_symbol_batch(&signed, limits()).unwrap().key();
            if matches!(case, Case::Roundtrip) {
                let mut distributor = SymbolDistributor::new(DistributionConfig {
                    consistency: ConsistencyLevel::All, max_concurrent: 2,
                    ack_timeout: Duration::from_secs(4), ..Default::default()
                });
                let replicas = [ReplicaInfo::new(replica, &endpoint.to_string())];
                let result = distributor.distribute(&cx, &encoded, &replicas, &transport, &security).await;
                assert!(result.quorum_achieved);
                assert_eq!(result.acks.len(), 1);
                assert_eq!(result.acks[0].symbols_received, 3);
                assert_eq!(result.symbols_distributed, 3);
                assert_eq!(retained.stats().batches, 1, "a receipt requires actual receiver storage");
                let fetched = transport.fetch_symbols(replica, key).await.unwrap();
                assert_eq!(fetched.len(), signed.len());
                for (actual, expected) in fetched.iter().zip(&signed) {
                    assert!(actual.is_verified());
                    assert_eq!(actual.symbol(), expected.symbol());
                    assert_eq!(actual.tag(), expected.tag());
                }
                // Capacity is one batch per origin: an identical repeat is still valid.
                transport.send_symbols(replica, signed).await.unwrap();
                assert_eq!(retained.stats().batches, 1);
                let mut wrong_key = key;
                wrong_key.digest[0] ^= 1;
                assert!(transport.fetch_symbols(replica, wrong_key).await.is_err());
                assert_eq!(distributor.metrics.acks_received_total, 1);
            } else {
                assert!(transport.send_symbols(replica, signed).await.is_err());
                assert_eq!(retained.stats().batches, 0);
            }
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    })));
    let report = server.block_on(async move {
        let cx = Cx::current().expect("server context");
        asupersync::time::timeout(cx.now(), Duration::from_secs(25), service.run(&cx)).await
    });
    // Join on every normal timeout/error path before asserting the server outcome.
    let _ = operator.begin_drain();
    let client_result = client.0.take().unwrap().join();
    let active = operator.active_connections();
    let no_leaks = server.diagnostics().find_leaked_obligations().is_empty();
    let shutdown = server.shutdown_timeout(Duration::from_secs(3));
    client_result.expect("native symbol client panicked");
    let report = report.expect("native service deadline").expect("service run");
    assert!(report.accepted_connections() >= 1);
    assert_eq!(active, 0);
    if matches!(case, Case::Roundtrip) {
        assert_eq!(report.accepted_connections(), 4);
        assert_eq!(report.failed_connections(), 0);
        assert_eq!(report.completed_connections(), 4);
    }
    assert!(no_leaks);
    assert!(shutdown);
}

#[test]
fn public_distribution_and_exact_fetch_use_real_mtls_storage() {
    for workers in [1, 2] { exercise(Case::Roundtrip, workers); }
}
#[test]
fn misrouted_replica_is_rejected_before_remote_publication() { exercise(Case::WrongTarget, 1); }
#[test]
fn wrong_symbol_key_cannot_receive_a_storage_acknowledgement() { exercise(Case::WrongSymbolKey, 1); }
#[test]
fn missing_mutual_tls_identity_never_reaches_symbol_store() { exercise(Case::MissingClientIdentity, 1); }
#[test]
fn ungranted_peer_never_reaches_symbol_store() { exercise(Case::UnauthorizedPeer, 1); }

const CHUNKED_FRAME_BYTES: usize = 8 * 1024;
const CHUNK_BYTES: usize = 1024;

fn chunked_batch_limits() -> SymbolBatchLimits {
    SymbolBatchLimits {
        max_encoded_bytes: 128 * 1024,
        max_symbols: 64,
        max_payload_bytes: 128 * 1024,
        max_decoded_bytes: 256 * 1024,
    }
}

fn chunked_symbols(key_seed: u64) -> Vec<AuthenticatedSymbol> {
    let security = SecurityContext::new(AuthKey::from_seed(key_seed));
    (0..32_u32)
        .map(|esi| {
            let data: Vec<_> = (0..2048)
                .map(|index| {
                    u8::try_from(index % 251).unwrap()
                        .wrapping_add(u8::try_from(esi).unwrap())
                })
                .collect();
            security.sign_symbol(&Symbol::new_for_test(71, 0, esi, &data))
        })
        .collect()
}

#[derive(Clone, Copy)]
enum ChunkedCase {
    Roundtrip,
    WrongSymbolKey,
    CorruptSymbolTag,
    DropAfterAcceptedChunk,
}

// These tests run the production listener and client on separate native runtimes.
// They prove bounded framing and in-memory retention, not independent processes,
// disk durability, remote cancellation/drain, or RaptorQ snapshot recovery.
fn exercise_chunked(case: ChunkedCase, workers: usize) {
    let receiver_seed = if matches!(case, ChunkedCase::WrongSymbolKey) { 43 } else { 42 };
    let store = Arc::new(SymbolReplicaStore::new(
        "replica-a", AuthKey::from_seed(receiver_seed), chunked_batch_limits(),
        SymbolStoreLimits {
            max_batches: 1,
            max_bytes: 128 * 1024,
            max_batches_per_peer: 1,
            max_bytes_per_peer: 128 * 1024,
        },
    ).unwrap());
    let staged = Arc::new(ChunkedSymbolService::new(
        Arc::clone(&store),
        SymbolChunkedLimits::new(
            CHUNK_BYTES, 2, 256 * 1024, 1, 128 * 1024, Duration::from_secs(120),
        ).unwrap(),
    ));
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::clone(&store)).unwrap();
    register_chunked_symbol_service(&mut registry, Arc::clone(&staged)).unwrap();
    let (acceptor, connector, pins) = tls(true);
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V1, registry.schema_registry().clone(),
    );
    policy.grant_tls_peer(
        NodeId::new("origin-a"), pins,
        [SYMBOL_SERVICE_COMPUTATION, SYMBOL_CHUNKED_SERVICE_COMPUTATION],
    ).unwrap();
    let hello = policy.hello_for(NodeId::new("origin-a"));
    let wire_limits = RemoteServiceWireLimits::new(CHUNKED_FRAME_BYTES);
    let server = RuntimeBuilder::current_thread().build().unwrap();
    let service = server.block_on(RemoteComputationService::bind(
        "127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_wire_limits(wire_limits)
            .with_max_connections(Some(4)).with_drain_timeout(Duration::from_secs(3)),
    )).unwrap();
    let endpoint = service.local_addr().unwrap();
    let operator = service.handle();
    let client_operator = operator.clone();
    let client_store = Arc::clone(&store);
    let client_staged = Arc::clone(&staged);
    let mut client = ClientJoin(Some(std::thread::spawn(move || {
        let _drain = DrainOnDrop(client_operator);
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async move {
            let cx = Cx::current().expect("native chunked client context");
            let client = RemoteComputationClient::new(
                endpoint, "localhost", connector,
                RemoteComputationClientConfig::new().with_wire_limits(wire_limits)
                    .with_max_attempts(1).with_connect_timeout(Duration::from_secs(2))
                    .with_attempt_timeout(Duration::from_secs(3)),
            ).unwrap();
            let transport = RemoteSymbolTransport::new_chunked_bounded(
                cx.clone(), hello.clone(), [("replica-a".to_owned(), client.clone())],
                Arc::new(AuthKey::from_seed(42)), chunked_batch_limits(), 1, CHUNK_BYTES,
            ).unwrap();
            let signed = chunked_symbols(42);
            let encoded = encode_symbol_batch(&signed, chunked_batch_limits()).unwrap();
            let key = encoded.key();
            let encoded_len = encoded.as_ref().len();
            assert!(encoded_len > 8 * CHUNKED_FRAME_BYTES,
                "fixture must not fit a single request or response frame");

            if matches!(case, ChunkedCase::Roundtrip) {
                // The same object, client and service ceiling cannot carry the
                // legacy whole-batch frame. This witnesses the actual boundary.
                let whole_batch = RemoteSymbolTransport::new_bounded(
                    cx.clone(), hello, [("replica-a".to_owned(), client)],
                    Arc::new(AuthKey::from_seed(42)), chunked_batch_limits(), 1,
                ).unwrap();
                let refused = whole_batch.send_symbols("replica-a", signed.clone()).await.unwrap_err();
                assert_eq!(refused.error_kind, asupersync::error::ErrorKind::ConnectionLost);
                assert_eq!(whole_batch.in_flight(), 0);
                assert_eq!(client_store.stats().batches, 0);
            }

            if matches!(case, ChunkedCase::WrongSymbolKey | ChunkedCase::CorruptSymbolTag) {
                let mut rejected = signed.clone();
                if matches!(case, ChunkedCase::CorruptSymbolTag) {
                    let mut tag = *rejected[17].tag().as_bytes();
                    tag[5] ^= 0x80;
                    rejected[17] = AuthenticatedSymbol::from_parts(
                        rejected[17].symbol().clone(), AuthenticationTag::from_bytes(tag),
                    );
                }
                let refused = transport.send_symbols("replica-a", rejected).await.unwrap_err();
                assert_eq!(refused.error_kind, asupersync::error::ErrorKind::AdmissionDenied,
                    "the authenticated service must refuse the commit, not merely lose its connection");
                assert_eq!(client_store.stats().batches, 0,
                    "complete bytes with an invalid symbol tag must not receive storage credit");
                assert_eq!(client_store.stats().bytes, 0);
                assert_eq!(client_staged.stats().uploads, 0);
                assert_eq!(client_staged.stats().reserved_bytes, 0);
                assert_eq!(client_staged.stats().received_bytes, 0);
                assert_eq!(transport.in_flight(), 0);
                if matches!(case, ChunkedCase::WrongSymbolKey) {
                    return;
                }
                // A refused final commit must release staging quota so the
                // correctly signed retry below can use the only per-peer slot.
            }

            if matches!(case, ChunkedCase::DropAfterAcceptedChunk) {
                let mut sending = Box::pin(transport.send_symbols("replica-a", signed.clone()));
                std::future::poll_fn(|task_cx| {
                    use std::future::Future;
                    use std::task::Poll;
                    match sending.as_mut().poll(task_cx) {
                        Poll::Ready(result) => panic!("upload completed before partial-stage witness: {result:?}"),
                        Poll::Pending => {
                            let observed = client_staged.stats();
                            if observed.received_bytes > 0 {
                                assert_eq!(observed.uploads, 1);
                                assert_eq!(observed.reserved_bytes, encoded_len);
                                assert!(observed.received_bytes < encoded_len);
                                assert_eq!(transport.in_flight(), 1);
                                assert_eq!(client_store.stats().batches, 0);
                                Poll::Ready(())
                            } else {
                                Poll::Pending
                            }
                        }
                    }
                }).await;
                drop(sending);
                assert_eq!(transport.in_flight(), 0,
                    "dropping the admitted future returns the clone-shared credit");
                assert_eq!(client_store.stats().batches, 0);
                // A lost client cannot synchronously roll back a remote stage.
                // The service's explicit expiry path reclaims it without
                // publishing a partial batch or altering existing storage.
                assert_eq!(client_staged.reap_expired(Time::from_nanos(u64::MAX)), 1);
                assert_eq!(client_staged.stats().uploads, 0);
                assert_eq!(client_staged.stats().reserved_bytes, 0);
                assert_eq!(client_staged.stats().received_bytes, 0);
            }

            let ack = transport.send_symbols("replica-a", signed.clone()).await.unwrap();
            assert_eq!(ack.replica_id, "replica-a");
            assert_eq!(ack.symbols_received, 32);
            assert_eq!(client_store.stats().batches, 1);
            assert_eq!(client_store.stats().bytes, encoded_len);
            assert_eq!(client_staged.stats().uploads, 0);
            assert_eq!(client_staged.stats().reserved_bytes, 0);
            assert_eq!(client_staged.stats().received_bytes, 0);
            assert_eq!(transport.in_flight(), 0);
            let fetched = transport.fetch_symbols("replica-a", key).await.unwrap();
            assert_eq!(fetched.len(), signed.len());
            for (actual, expected) in fetched.iter().zip(&signed) {
                assert!(actual.is_verified());
                assert_eq!(actual.symbol(), expected.symbol());
                assert_eq!(actual.tag(), expected.tag());
            }
            assert_eq!(transport.in_flight(), 0);
            transport.send_symbols("replica-a", signed).await.unwrap();
            assert_eq!(client_store.stats().batches, 1,
                "an identical retry remains valid at the retained-store quota");
            let mut wrong_digest = key;
            wrong_digest.digest[0] ^= 1;
            assert!(transport.fetch_symbols("replica-a", wrong_digest).await.is_err());
            assert_eq!(transport.in_flight(), 0);
            assert_eq!(client_store.stats().bytes, encoded_len);
            assert_eq!(client_staged.stats().uploads, 0);
            assert_eq!(client_staged.stats().reserved_bytes, 0);
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    })));
    let report = server.block_on(async move {
        let cx = Cx::current().expect("native chunked server context");
        asupersync::time::timeout(cx.now(), Duration::from_secs(60), service.run(&cx)).await
    });
    let _ = operator.begin_drain();
    let client_result = client.0.take().unwrap().join();
    let active = operator.active_connections();
    let no_leaks = server.diagnostics().find_leaked_obligations().is_empty();
    let shutdown = server.shutdown_timeout(Duration::from_secs(3));
    client_result.expect("native chunked symbol client panicked");
    let report = report.expect("native chunked service deadline").expect("chunked service run");
    assert!(report.accepted_connections() > 8,
        "the observed receiver must handle multiple bounded exchanges");
    assert_eq!(report.panicked_connections(), 0);
    assert_eq!(active, 0);
    assert_eq!(staged.stats().uploads, 0);
    assert_eq!(staged.stats().reserved_bytes, 0);
    assert_eq!(staged.stats().received_bytes, 0);
    assert!(no_leaks);
    assert!(shutdown);
}

#[test]
fn chunked_symbol_transfer_and_exact_fetch_exceed_native_mtls_frame_limit() {
    for workers in [1, 2] { exercise_chunked(ChunkedCase::Roundtrip, workers); }
}

#[test]
fn chunked_symbol_commit_rejects_wrong_key_and_corrupt_tags_without_storage_credit() {
    exercise_chunked(ChunkedCase::WrongSymbolKey, 1);
    exercise_chunked(ChunkedCase::CorruptSymbolTag, 2);
}

#[test]
fn dropped_native_chunked_upload_expires_partial_stage_then_reuses_transport_capacity() {
    for workers in [1, 2] { exercise_chunked(ChunkedCase::DropAfterAcceptedChunk, workers); }
}


// Publisher-process restart against retained receiver state. This does not claim
// receiver restart durability, recovery of Rust tasks, or 4 MiB snapshot decoding.
#[cfg(unix)]
mod attempt_restart {
    use super::*;
    use asupersync::distributed::symbol_service::RemoteSymbolError;
    use asupersync::sync::Notify;
    use asupersync::remote::{
        ComputationName, IdempotencyKey, RemoteInput, RemotePeerHello, RemoteServiceWireOutcome,
        RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId, SpawnRequest,
    };
    use std::fs::{File, OpenOptions};
    use std::io::{self, BufRead, Read, Write};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    const PREFIX: &str = "ASUP_SYMBOL_ATTEMPT_";
    const PERSISTED_ATTEMPT: u64 = 0xa173_b820_c591_d604;
    const ATTEMPT_CHUNK_BYTES: usize = 512;

    fn store() -> Arc<SymbolReplicaStore> {
        Arc::new(SymbolReplicaStore::new(
            "replica-a", AuthKey::from_seed(42), chunked_batch_limits(),
            SymbolStoreLimits { max_batches: 1, max_bytes: 128 * 1024,
                max_batches_per_peer: 1, max_bytes_per_peer: 128 * 1024 },
        ).unwrap())
    }

    fn staging(store: Arc<SymbolReplicaStore>) -> Arc<ChunkedSymbolService> {
        Arc::new(ChunkedSymbolService::new(store, SymbolChunkedLimits::new(
            CHUNK_BYTES, 1, 128 * 1024, 1, 128 * 1024, Duration::from_secs(180),
        ).unwrap()))
    }

    fn intent_path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir();
        loop {
            let path = directory.join(format!("asupersync-symbol-attempt-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match OpenOptions::new().create_new(true).write(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(&PERSISTED_ATTEMPT.to_le_bytes()).unwrap();
                    file.sync_all().unwrap();
                    File::open(&directory).unwrap().sync_all().unwrap();
                    return path; // Retain the fixture; no deletion on failure or success.
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("persist publisher intent: {error}"),
            }
        }
    }

    // Independent wire fixture: a real authenticated publisher stops between
    // acknowledged frames. It cannot send the rest while the parent kills it.
    async fn save_first_chunk(
        cx: &Cx,
        client: &RemoteComputationClient,
        hello: &RemotePeerHello,
        signed: &[AuthenticatedSymbol],
        attempt: u64,
    ) {
        let batch = encode_symbol_batch(signed, chunked_batch_limits()).unwrap();
        let key = batch.key();
        let mut metadata = Vec::with_capacity(68);
        metadata.extend_from_slice(&key.object_id.as_u128().to_le_bytes());
        metadata.extend_from_slice(&key.digest);
        metadata.extend_from_slice(&attempt.to_le_bytes());
        metadata.extend_from_slice(&(batch.as_ref().len() as u64).to_le_bytes());
        metadata.extend_from_slice(&batch.symbol_count().to_le_bytes());
        assert_eq!(metadata.len(), 68);
        for (operation, received) in [(1_u8, 0_usize), (2, ATTEMPT_CHUNK_BYTES)] {
            let mut input = b"ASUPCHN\0".to_vec();
            input.extend_from_slice(&1_u32.to_le_bytes());
            input.push(operation);
            input.push(9);
            input.extend_from_slice(b"replica-a");
            input.extend_from_slice(&metadata);
            if operation == 2 {
                input.extend_from_slice(&0_u64.to_le_bytes());
                input.extend_from_slice(&batch.as_ref()[..ATTEMPT_CHUNK_BYTES]);
            }
            let task = RemoteTaskId::next();
            let spawn = SpawnRequest {
                remote_task_id: task,
                computation: ComputationName::new(SYMBOL_CHUNKED_SERVICE_COMPUTATION),
                input: RemoteInput::new(input),
                lease: client.config().attempt_timeout(),
                idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())),
                budget: None,
                origin_node: hello.peer_node().clone(),
                origin_region: cx.region_id(),
                origin_task: cx.task_id(),
            };
            let wire = RemoteServiceWireRequest::from_spawn_request(hello.clone(), &spawn).unwrap();
            let response = client.call(cx, &wire).await.unwrap();
            let RemoteServiceWireResponse::Outcome {
                remote_task_id,
                outcome: RemoteServiceWireOutcome::Success(progress),
            } = response else {
                panic!("chunked BEGIN/CHUNK did not return authenticated progress");
            };
            assert_eq!(remote_task_id, task.raw());
            assert_eq!(progress.len(), 92);
            assert_eq!(&progress[..8], b"ASUPPRG\0");
            assert_eq!(&progress[8..12], &1_u32.to_le_bytes());
            assert_eq!(&progress[12..80], metadata.as_slice());
            assert_eq!(u64::from_le_bytes(progress[80..88].try_into().unwrap()), received as u64);
            assert_eq!(u32::from_le_bytes(progress[88..92].try_into().unwrap()), CHUNK_BYTES as u32);
        }
    }

    #[test]
    #[ignore = "worker invoked explicitly by the publisher restart acceptance test"]
    fn chunked_upload_client_process() {
        // Each independent publisher has the same process-local counter start;
        // the externally persisted upload identity must be what survives.
        assert_eq!(asupersync::remote::RemoteTaskId::next().raw(), 1);
        let endpoint: SocketAddr = std::env::var("ASUP_SYMBOL_ATTEMPT_ENDPOINT").unwrap().parse().unwrap();
        let mode = std::env::var("ASUP_SYMBOL_ATTEMPT_MODE").unwrap();
        let workers: usize = std::env::var("ASUP_SYMBOL_ATTEMPT_WORKERS").unwrap().parse().unwrap();
        let mut intent = [0_u8; 8];
        File::open(std::env::var_os("ASUP_SYMBOL_ATTEMPT_INTENT").unwrap())
            .unwrap().read_exact(&mut intent).unwrap();
        let attempt = u64::from_le_bytes(intent);
        assert_eq!(attempt, PERSISTED_ATTEMPT);
        let mut registry = RemoteComputationRegistry::new();
        register_chunked_symbol_service(&mut registry, staging(store())).unwrap();
        let policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
        let hello = policy.hello_for(NodeId::new("origin-a"));
        let (_, connector, _) = tls(true);
        let resume = Arc::new(Notify::new());
        let input = if mode == "finish" {
            let resume = Arc::clone(&resume);
            Some(thread::spawn(move || {
                let mut byte = [0];
                io::stdin().read_exact(&mut byte).expect("parent releases exact retry");
                resume.notify_one();
            }))
        } else { None };
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        println!("{PREFIX}READY");
        io::stdout().flush().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("fresh publisher owner");
            asupersync::time::timeout(cx.now(), Duration::from_secs(75), async {
                let client = RemoteComputationClient::new(
                    endpoint, "localhost", connector,
                    RemoteComputationClientConfig::new()
                        .with_wire_limits(RemoteServiceWireLimits::new(CHUNKED_FRAME_BYTES))
                        .with_max_attempts(1).with_connect_timeout(Duration::from_secs(3))
                        .with_attempt_timeout(Duration::from_secs(5)),
                ).unwrap();
                let transport = RemoteSymbolTransport::new_chunked_bounded(
                    cx.clone(), hello.clone(), [("replica-a".to_owned(), client.clone())],
                    Arc::new(AuthKey::from_seed(42)), chunked_batch_limits(), 1, ATTEMPT_CHUNK_BYTES,
                ).unwrap();
                let signed = chunked_symbols(42);
                if mode == "partial" {
                    save_first_chunk(&cx, &client, &hello, &signed, attempt).await;
                    println!("{PREFIX}PARTIAL_SAVED");
                    io::stdout().flush().unwrap();
                    std::future::pending::<()>().await;
                    unreachable!("the first publisher is parked between acknowledged frames");
                }
                assert_eq!(mode, "finish");
                let whole = RemoteSymbolTransport::new_bounded(
                    cx.clone(), hello, [("replica-a".to_owned(), client)],
                    Arc::new(AuthKey::from_seed(42)), chunked_batch_limits(), 1,
                ).unwrap();
                assert!(matches!(
                    whole.send_symbols_with_attempt("replica-a", signed.clone(), attempt).await,
                    Err(RemoteSymbolError::Configuration),
                ));
                assert_eq!(whole.in_flight(), 0);
                let mut different = signed.clone();
                different[0] = SecurityContext::new(AuthKey::from_seed(42))
                    .sign_symbol(&Symbol::new_for_test(71, 0, 0, &[255; 2048]));
                assert!(matches!(
                    transport.send_symbols_with_attempt("replica-a", different, attempt).await,
                    Err(RemoteSymbolError::Refused),
                ));
                assert_eq!(transport.in_flight(), 0);
                println!("{PREFIX}MISMATCH_REFUSED");
                io::stdout().flush().unwrap();
                // The parent checks the retained prefix while this second
                // publisher is parked, then permits the exact retry.
                resume.notified().await;
                let encoded = encode_symbol_batch(&signed, chunked_batch_limits()).unwrap();
                let ack = transport.send_symbols_with_attempt("replica-a", signed.clone(), attempt).await.unwrap();
                assert_eq!(ack.replica_id, "replica-a");
                assert_eq!(ack.symbols_received, signed.len() as u32);
                assert_eq!(transport.in_flight(), 0);
                let fetched = transport.fetch_symbols("replica-a", encoded.key()).await.unwrap();
                assert_eq!(fetched.len(), signed.len());
                for (actual, expected) in fetched.iter().zip(&signed) {
                    assert!(actual.is_verified());
                    assert_eq!(actual.symbol(), expected.symbol());
                    assert_eq!(actual.tag(), expected.tag());
                }
                let repeated = transport.send_symbols_with_attempt("replica-a", signed, attempt).await.unwrap();
                assert_eq!(repeated.replica_id, "replica-a");
                assert_eq!(repeated.symbols_received, ack.symbols_received);
                assert_eq!(transport.in_flight(), 0);
            }).await.expect("publisher workflow deadline");
        });
        if let Some(input) = input { input.join().expect("publisher control thread"); }
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        println!("{PREFIX}DONE");
        io::stdout().flush().unwrap();
    }

    struct Publisher {
        child: Child,
        input: Option<ChildStdin>,
        pump: Option<JoinHandle<()>>,
        messages: mpsc::Receiver<String>,
        reaped: bool,
    }

    impl Publisher {
        fn start(endpoint: SocketAddr, path: &Path, mode: &str, workers: usize) -> Self {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "attempt_restart::chunked_upload_client_process",
                    "--ignored", "--nocapture", "--test-threads=1"])
                .env("ASUP_SYMBOL_ATTEMPT_ENDPOINT", endpoint.to_string())
                .env("ASUP_SYMBOL_ATTEMPT_INTENT", path)
                .env("ASUP_SYMBOL_ATTEMPT_MODE", mode)
                .env("ASUP_SYMBOL_ATTEMPT_WORKERS", workers.to_string())
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
                .spawn().expect("start independent publisher");
            let stdout = child.stdout.take().unwrap();
            let input = child.stdin.take();
            let (tx, messages) = mpsc::sync_channel(8);
            let mut process = Self { child, input, pump: None, messages, reaped: false };
            process.pump = Some(thread::spawn(move || {
                for line in io::BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break; };
                    if let Some((_, message)) = line.split_once(PREFIX) {
                        let _ = tx.try_send(message.to_owned());
                    }
                }
            }));
            process.message("READY", Duration::from_secs(10));
            process
        }

        fn message(&self, expected: &str, timeout: Duration) {
            assert_eq!(self.messages.recv_timeout(timeout).expect("publisher phase receipt"), expected);
        }

        fn resume(&mut self) {
            let input = self.input.as_mut().expect("publisher control");
            input.write_all(&[1]).unwrap();
            input.flush().unwrap();
        }

        fn reap(&mut self, crash: bool) -> (ExitStatus, bool) {
            assert!(!self.reaped);
            if crash { self.child.kill().expect("terminate publisher after partial-stage witness"); }
            drop(self.input.take());
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut forced = false;
            let status = loop {
                if let Some(status) = self.child.try_wait().expect("poll publisher") { break status; }
                if Instant::now() >= deadline {
                    forced = true;
                    let _ = self.child.kill();
                    break self.child.wait().expect("reap watchdog publisher");
                }
                thread::sleep(Duration::from_millis(5));
            };
            self.reaped = true;
            if let Some(pump) = self.pump.take() { pump.join().expect("publisher stdout"); }
            (status, forced)
        }

        fn crash(mut self) {
            let (status, forced) = self.reap(true);
            assert!(!forced && !status.success(), "the first publisher must be killed and reaped");
        }

        fn finish(mut self) {
            self.message("DONE", Duration::from_secs(75));
            let (status, forced) = self.reap(false);
            assert!(!forced && status.success(), "fresh publisher must exit successfully");
        }
    }

    impl Drop for Publisher {
        fn drop(&mut self) {
            if self.reaped { return; }
            let _ = self.child.kill();
            drop(self.input.take());
            let _ = self.child.wait();
            self.reaped = true;
            if let Some(pump) = self.pump.take() { let _ = pump.join(); }
        }
    }

    fn exercise(workers: usize) {
        let path = intent_path();
        let store = store();
        let staged = staging(Arc::clone(&store));
        let encoded_len = encode_symbol_batch(&chunked_symbols(42), chunked_batch_limits()).unwrap().as_ref().len();
        let mut registry = RemoteComputationRegistry::new();
        register_chunked_symbol_service(&mut registry, Arc::clone(&staged)).unwrap();
        let (acceptor, _, pins) = tls(true);
        let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
        policy.grant_tls_peer(NodeId::new("origin-a"), pins, [SYMBOL_CHUNKED_SERVICE_COMPUTATION]).unwrap();
        let server = RuntimeBuilder::current_thread().build().unwrap();
        let service = server.block_on(RemoteComputationService::bind(
            "127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new()
                .with_wire_limits(RemoteServiceWireLimits::new(CHUNKED_FRAME_BYTES))
                .with_max_connections(Some(4)).with_drain_timeout(Duration::from_secs(3)),
        )).unwrap();
        let endpoint = service.local_addr().unwrap();
        let operator = service.handle();
        let client_operator = operator.clone();
        let retained = Arc::clone(&store);
        let partial = Arc::clone(&staged);
        let mut controller = ClientJoin(Some(thread::spawn(move || {
            let _drain = DrainOnDrop(client_operator.clone());
            let first = Publisher::start(endpoint, &path, "partial", workers);
            first.message("PARTIAL_SAVED", Duration::from_secs(15));
            let observed = partial.stats();
            assert_eq!(observed.uploads, 1);
            assert_eq!(observed.reserved_bytes, encoded_len);
            assert_eq!(observed.received_bytes, ATTEMPT_CHUNK_BYTES);
            assert!(observed.received_bytes < encoded_len);
            assert_eq!(retained.stats().batches, 0);
            first.crash();
            let deadline = Instant::now() + Duration::from_secs(10);
            while client_operator.active_connections() != 0 {
                assert!(Instant::now() < deadline, "killed publisher connection did not retire");
                thread::yield_now();
            }
            let persisted = partial.stats();
            assert_eq!(persisted.uploads, 1);
            assert_eq!(persisted.reserved_bytes, encoded_len);
            assert_eq!(persisted.received_bytes, ATTEMPT_CHUNK_BYTES);
            assert!(persisted.received_bytes < encoded_len);
            assert_eq!(retained.stats().batches, 0);
            let mut second = Publisher::start(endpoint, &path, "finish", workers);
            second.message("MISMATCH_REFUSED", Duration::from_secs(15));
            assert_eq!(partial.stats(), persisted,
                "wrong bytes under the persisted attempt must preserve its exact prefix and charge");
            assert_eq!(retained.stats().batches, 0);
            second.resume();
            second.finish();
            assert_eq!(retained.stats().batches, 1);
            assert_eq!(retained.stats().bytes, encoded_len);
            assert_eq!(partial.stats().uploads, 0);
            assert_eq!(partial.stats().reserved_bytes, 0);
            assert_eq!(partial.stats().received_bytes, 0);
        })));
        let report = server.block_on(async {
            let cx = Cx::current().expect("receiver owner");
            asupersync::time::timeout(cx.now(), Duration::from_secs(100), service.run(&cx)).await
        });
        let _ = operator.begin_drain();
        let result = controller.0.take().unwrap().join();
        let active = operator.active_connections();
        let no_leaks = server.diagnostics().find_leaked_obligations().is_empty();
        let shutdown = server.shutdown_timeout(Duration::from_secs(3));
        result.expect("publisher restart controller");
        let report = report.expect("receiver workflow deadline").expect("receiver drain");
        assert!(report.accepted_connections() > 8);
        assert_eq!(report.panicked_connections(), 0);
        assert_eq!(active, 0);
        assert!(no_leaks && shutdown);
        assert_eq!(store.stats().batches, 1);
        assert_eq!(staged.stats().reserved_bytes, 0);
    }

    #[test]
    fn persisted_attempt_resumes_after_publisher_process_crash_and_reconciles_completed_upload() {
        for workers in [1, 2] { exercise(workers); }
    }
}
