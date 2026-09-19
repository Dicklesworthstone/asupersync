//! Real production mTLS service/client plus public symbol distribution and fetch.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::distributed::distribution::{DistributionConfig, DistributorTransport, SymbolDistributor};
use asupersync::distributed::symbol_service::{
    RemoteSymbolTransport, SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits, SymbolReplicaStore,
    SymbolStoreLimits, encode_symbol_batch, register_symbol_service,
};
use asupersync::distributed::EncodedState;
use asupersync::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use asupersync::remote::{
    NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemotePeerAdmissionPolicy, RemoteProtocolVersion,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AuthKey, SecurityContext};
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
