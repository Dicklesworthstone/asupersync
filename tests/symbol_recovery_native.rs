//! Real mTLS storage and fetch into the existing multi-block snapshot decoder.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::distributed::distribution::DistributorTransport;
use asupersync::distributed::symbol_service::{
    RemoteSymbolError, RemoteSymbolTransport, SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits,
    SymbolReplicaStore, SymbolStoreLimits, encode_symbol_batch, register_symbol_service,
};
use asupersync::distributed::symbol_service::recovery::{
    RemoteRecoveryConfig, RemoteRecoveryError, ReplicaFetch, SnapshotDecodeLimits, SnapshotIdentity,
};
use asupersync::distributed::{EncodingConfig, RegionSnapshot, StateEncoder};
use asupersync::remote::{
    NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemotePeerAdmissionPolicy, RemoteProtocolVersion,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AuthKey, SecurityContext};
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::util::{ArenaIndex, DetRng};
use asupersync::{Cx, types::{RegionId, Time}};
use std::sync::Arc;
use std::time::Duration;

fn limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 32768, max_symbols: 64, max_payload_bytes: 16384, max_decoded_bytes: 65536 }
}
struct Drain(RemoteComputationServiceHandle);
impl Drop for Drain { fn drop(&mut self) { let _ = self.0.begin_drain(); } }
struct Join(Option<std::thread::JoinHandle<()>>);
impl Drop for Join { fn drop(&mut self) { if let Some(thread) = self.0.take() { let _ = thread.join(); } } }

#[derive(Clone, Copy)]
enum Case { Recover, Quorum, WrongSnapshotKey, WrongProvenance }

fn exercise(case: Case) {
    let store = Arc::new(SymbolReplicaStore::new("replica-a", AuthKey::from_seed(42), limits(),
        SymbolStoreLimits { max_batches: 2, max_bytes: 65536, max_batches_per_peer: 2, max_bytes_per_peer: 65536 }).unwrap());
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::clone(&store)).unwrap();
    let certificate = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone()).client_auth(ClientAuth::Required(roots)).build().unwrap();
    let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate).identity(chain, key).build().unwrap();
    let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(NodeId::new("origin-a"), pins, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    let hello = policy.hello_for(NodeId::new("origin-a"));
    let server = RuntimeBuilder::current_thread().build().unwrap();
    let service = server.block_on(RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_max_connections(Some(4)).with_drain_timeout(Duration::from_secs(3)))).unwrap();
    let endpoint = service.local_addr().unwrap();
    let operator = service.handle(); let client_operator = operator.clone();
    let mut client_thread = Join(Some(std::thread::spawn(move || {
        let _drain = Drain(client_operator);
        let runtime = RuntimeBuilder::multi_thread().worker_threads(2).build().unwrap();
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            // One route deliberately names the wrong receiver on the same
            // authenticated server; its refusal must not become a quorum vote.
            let routes = || ["replica-a", "unavailable"].map(|replica| {
                let client = RemoteComputationClient::new(endpoint, "localhost", connector.clone(),
                    RemoteComputationClientConfig::new().with_max_attempts(1)
                        .with_connect_timeout(Duration::from_secs(1)).with_attempt_timeout(Duration::from_secs(2))).unwrap();
                (replica.to_owned(), client)
            });
            let denied = RemoteSymbolTransport::new_bounded(cx.clone(), hello.clone(), routes(), Arc::new(AuthKey::from_seed(42)), limits(), 0).unwrap();
            let transport = RemoteSymbolTransport::new_bounded(cx.clone(), hello, routes(), Arc::new(AuthKey::from_seed(42)), limits(), 2).unwrap();
            let mut snapshot = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(9, 3)));
            snapshot.origin_id = 77; snapshot.epoch = 5; snapshot.sequence = 8; snapshot.metadata = vec![83; 768];
            snapshot.sign(&AuthKey::from_seed(88));
            let mut expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 77, epoch: 5, sequence: 8 };
            let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 128, max_source_blocks: 2,
                min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(3));
            let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
            let params = encoded.params;
            let security = SecurityContext::new(AuthKey::from_seed(42));
            let signed: Vec<_> = encoded.symbols.iter().map(|s| security.sign_symbol(s)).collect();
            let batch_key = encode_symbol_batch(&signed, limits()).unwrap().key();
            assert!(matches!(denied.fetch_symbols("replica-a", batch_key).await, Err(RemoteSymbolError::Admission)));
            assert!(denied.send_symbols("replica-a", signed.clone()).await.is_err());
            assert_eq!(denied.in_flight(), 0);
            assert_eq!(store.stats().batches, 0, "deny-all must not publish remotely");
            transport.send_symbols("replica-a", signed).await.unwrap();
            assert_eq!(transport.in_flight(), 0);
            assert_eq!(store.stats().batches, 1);
            drop(snapshot); drop(encoded); drop(security);
            let requests = [
                ReplicaFetch { replica_id: "unavailable".into(), key: batch_key },
                ReplicaFetch { replica_id: "replica-a".into(), key: batch_key },
            ];
            if matches!(case, Case::WrongProvenance) { expected.epoch += 1; }
            let config = RemoteRecoveryConfig { max_replicas: 2, max_concurrent_requests: 2,
                required_replicas: if matches!(case, Case::Quorum) { 2 } else { 1 },
                recovery_timeout: Duration::from_secs(5), replica_timeout: Duration::from_secs(3),
                max_received_symbols: 128, max_received_payload_bytes: 32768 };
            let snapshot_key = AuthKey::from_seed(if matches!(case, Case::WrongSnapshotKey) { 89 } else { 88 });
            let result = transport.recover_snapshot(&requests, config, params, expected,
                SnapshotDecodeLimits { max_snapshot_bytes: 4096, max_source_symbols_per_block: 32, max_source_blocks: 4 }, &snapshot_key).await;
            assert_eq!(transport.in_flight(), 0, "all network owners retired before output");
            match case {
                Case::Recover => { let recovered = result.unwrap(); assert_eq!(recovered.metadata, vec![83; 768]); assert_eq!(recovered.sequence, 8); }
                Case::Quorum => assert!(matches!(result, Err(RemoteRecoveryError::Quorum { required: 2, received: 1, .. }))),
                Case::WrongSnapshotKey => assert!(matches!(result, Err(RemoteRecoveryError::Decode))),
                Case::WrongProvenance => assert!(matches!(result, Err(RemoteRecoveryError::SnapshotIdentity))),
            }
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    })));
    let result = server.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(25), service.run(&cx)).await
    });
    let _ = operator.begin_drain();
    let joined = client_thread.0.take().unwrap().join();
    let active = operator.active_connections();
    let no_leaks = server.diagnostics().find_leaked_obligations().is_empty();
    let shutdown = server.shutdown_timeout(Duration::from_secs(3));
    joined.expect("native recovery client panicked");
    let report = result.expect("bounded service run").expect("service exit");
    assert_eq!(report.accepted_connections(), 3, "only one put and two admitted fetches");
    assert_eq!(active, 0); assert!(no_leaks); assert!(shutdown);
}

#[test]
fn authenticated_network_snapshot_recovery_survives_a_refused_replica() { exercise(Case::Recover); }
#[test]
fn native_recovery_never_reduces_its_quorum_requirement() { exercise(Case::Quorum); }
#[test]
fn native_recovery_requires_the_independent_snapshot_key() { exercise(Case::WrongSnapshotKey); }
#[test]
fn native_recovery_rejects_a_signed_snapshot_from_the_wrong_epoch() { exercise(Case::WrongProvenance); }
