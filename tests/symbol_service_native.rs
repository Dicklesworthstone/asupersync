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
