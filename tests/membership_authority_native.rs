//! Real mTLS named-computation delivery of explicitly authorized SWIM decisions.
//! Lease IDs are test-local fixtures: these tests verify the controller/outbox,
//! not automatic RuntimeState obligation abort or remote-task termination.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::distributed::membership::{MembershipEvent, MembershipKind, Packet, Payload, Rumor, Swim, SwimConfig};
use asupersync::distributed::membership::authority::{
    MembershipControlError, MembershipControllerLimits, MembershipFloor, MembershipLeaseController,
    MembershipRevocationReason, MembershipUpdate,
};
use asupersync::distributed::membership::service::{
    MEMBERSHIP_SERVICE_COMPUTATION, MembershipDeliveryError, register_membership_service,
    submit_membership_update,
};
use asupersync::remote::{
    Lease, NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemotePeerAdmissionPolicy, RemoteProtocolVersion,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::AuthKey;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::{Cx, types::{ObligationId, RegionId, TaskId, Time}};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

fn authority() -> NodeId { NodeId::new("controller-authority") }
fn member() -> NodeId { NodeId::new("worker") }
fn fixture_lease(id: u32, now: Time) -> Lease {
    Lease::new(ObligationId::new_for_test(id, 1), RegionId::new_for_test(1, 1),
        TaskId::new_for_test(1, 1), Duration::from_secs(30), now)
}
fn signed(event: MembershipEvent, sequence: u64, key_seed: u64) -> Vec<u8> {
    MembershipUpdate { event, sequence }.authenticated_bytes(&authority(), 7, &AuthKey::from_seed(key_seed)).unwrap()
}
fn decision(kind: MembershipKind, incarnation: u64, sequence: u64) -> Vec<u8> {
    signed(MembershipEvent { node: member(), incarnation, kind }, sequence, 42)
}
fn detected(swim: &mut Swim, kind: MembershipKind) -> MembershipEvent {
    let event = swim.drain_events().into_iter().find(|event| event.node == member()).expect("actual detector event");
    assert_eq!(event.kind, kind); event
}
struct Drain(RemoteComputationServiceHandle);
impl Drop for Drain { fn drop(&mut self) { let _ = self.0.begin_drain(); } }
struct Join(Option<std::thread::JoinHandle<()>>);
impl Drop for Join { fn drop(&mut self) { if let Some(thread) = self.0.take() { let _ = thread.join(); } } }
struct HoldController {
    release: std::sync::mpsc::SyncSender<()>,
    worker: Option<std::thread::JoinHandle<bool>>,
}
impl HoldController {
    fn start(controller: Arc<Mutex<MembershipLeaseController>>) -> Self {
        let (ready, wait_ready) = std::sync::mpsc::sync_channel(1);
        let (release, wait_release) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _guard = controller.lock();
            let _ = ready.send(());
            // A blocking-lock regression must fail, not hang the test process.
            wait_release.recv_timeout(Duration::from_secs(8)).is_ok()
        });
        let holder = Self { release, worker: Some(worker) };
        wait_ready.recv_timeout(Duration::from_secs(2)).expect("controller actually locked");
        holder
    }
    fn finish(mut self) {
        let _ = self.release.try_send(());
        assert!(self.worker.take().unwrap().join().unwrap(), "controller holder required watchdog release");
    }
}
impl Drop for HoldController {
    fn drop(&mut self) {
        let _ = self.release.try_send(());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
#[derive(Clone, Copy)]
enum Case { Lifecycle, WrongKey, WrongPeer, Busy }

fn exercise(case: Case, workers: usize) {
    let controller = Arc::new(Mutex::new(MembershipLeaseController::new(authority(), 7, AuthKey::from_seed(42),
        vec![MembershipFloor { node: member(), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 4 }).unwrap()));
    let mut registry = RemoteComputationRegistry::new();
    register_membership_service(&mut registry, Arc::clone(&controller)).unwrap();
    let certificate = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone()).client_auth(ClientAuth::Required(roots)).build().unwrap();
    let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate).identity(chain, key)
        .with_certificate_pins(pins.clone()).build().unwrap();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(authority(), pins.clone(), [MEMBERSHIP_SERVICE_COMPUTATION]).unwrap();
    // Deliberately grant a second TLS identity the computation to prove that the
    // handler's independent authority check prevents capability misconfiguration.
    let observer = NodeId::new("observer");
    policy.grant_tls_peer(observer.clone(), pins, [MEMBERSHIP_SERVICE_COMPUTATION]).unwrap();
    let hello = policy.hello_for(if matches!(case, Case::WrongPeer) { observer } else { authority() });
    let server = RuntimeBuilder::current_thread().build().unwrap();
    let service = server.block_on(RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_max_connections(Some(4))
            .with_drain_timeout(Duration::from_secs(3)))).unwrap();
    let endpoint = service.local_addr().unwrap();
    let operator = service.handle(); let client_operator = operator.clone();
    let owner = Arc::clone(&controller);
    // A witness confirms the external owner holds the lock before any request.
    // Watchdog release fails acceptance but prevents a regression from hanging.
    let holder = if matches!(case, Case::Busy) { Some(HoldController::start(Arc::clone(&controller))) } else { None };
    let mut client_thread = Join(Some(std::thread::spawn(move || {
        let _drain = Drain(client_operator);
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async move {
            let cx = Cx::current().expect("native client context");
            let client = RemoteComputationClient::new(endpoint, "localhost", connector,
                RemoteComputationClientConfig::new().with_max_attempts(1)
                    .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(3))).unwrap();
            if !matches!(case, Case::Lifecycle) {
                let data = signed(MembershipEvent { node: member(), incarnation: 0, kind: MembershipKind::Alive },
                    1, if matches!(case, Case::WrongKey) { 43 } else { 42 });
                let result = submit_membership_update(&cx, &client, &hello, &data).await;
                assert!(matches!(result, Err(MembershipDeliveryError::Refused)),
                    "must reach authenticated application refusal, not fail at TCP/TLS: {result:?}");
                return;
            }

            // SWIM remains an observation source. This provisioned authority
            // explicitly approves/signs each selected observation for publication.
            let mut swim = Swim::new(NodeId::new("detector"), SwimConfig::default(), 5);
            swim.add_peer(0, member());
            let alive = signed(detected(&mut swim, MembershipKind::Alive), 1, 42);
            submit_membership_update(&cx, &client, &hello, &alive).await.unwrap();
            let old = owner.lock().try_grant(&member(), 0, fixture_lease(1, cx.now()), cx.now()).unwrap();
            let _ = swim.handle(0, NodeId::new("accuser"), Packet { payload: Payload::Ping { seq: 1 },
                gossip: vec![Rumor::suspect(member(), 0, NodeId::new("accuser"))] });
            let suspect = signed(detected(&mut swim, MembershipKind::Suspect), 2, 42);
            submit_membership_update(&cx, &client, &hello, &suspect).await.unwrap();
            let refused = owner.lock().try_grant(&member(), 0, fixture_lease(2, cx.now()), cx.now()).unwrap_err();
            assert!(matches!(refused.error, MembershipControlError::GrantDenied));
            assert_eq!(owner.lock().active_leases(&member()), 1);

            let _ = swim.tick(30_000);
            let dead = signed(detected(&mut swim, MembershipKind::Dead), 3, 42);
            submit_membership_update(&cx, &client, &hello, &dead).await.unwrap();
            submit_membership_update(&cx, &client, &hello, &dead).await.unwrap();
            {
                let state = owner.lock();
                assert_eq!(state.active_leases(&member()), 0);
                assert_eq!(state.revocations().len(), 1);
                assert_eq!(state.revocations()[0].lease, old);
                assert_eq!(state.revocations()[0].reason, MembershipRevocationReason::Terminal);
            }
            let same_incarnation = decision(MembershipKind::Alive, 0, 4);
            assert!(matches!(submit_membership_update(&cx, &client, &hello, &same_incarnation).await,
                Err(MembershipDeliveryError::Refused)));
            let rejoin = decision(MembershipKind::Alive, 1, 4);
            submit_membership_update(&cx, &client, &hello, &rejoin).await.unwrap();
            assert!(matches!(owner.lock().renew(&old, Duration::from_secs(30), cx.now()), Err(MembershipControlError::UnknownLease)));
            assert!(matches!(owner.lock().try_grant(&member(), 1, fixture_lease(1, cx.now()), cx.now()).unwrap_err().error,
                MembershipControlError::ReusedLease));
            let fresh = owner.lock().try_grant(&member(), 1, refused.lease, cx.now()).unwrap();
            let delayed_death = decision(MembershipKind::Dead, 0, 100);
            assert!(matches!(submit_membership_update(&cx, &client, &hello, &delayed_death).await,
                Err(MembershipDeliveryError::Refused)));
            let mut state = owner.lock();
            assert_eq!(state.active_leases(&member()), 1);
            assert_eq!(state.stamp(&member()).unwrap().incarnation, 1);
            assert_eq!(state.stamp(&member()).unwrap().sequence, 4);
            assert!(state.release(&fresh, cx.now()).unwrap().is_released());
            assert_eq!(state.revocations().len(), 1, "remote receipts must not consume owner cleanup instructions");
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    })));
    let result = server.block_on(async move {
        let cx = Cx::current().expect("native server context");
        asupersync::time::timeout(cx.now(), Duration::from_secs(30), service.run(&cx)).await
    });
    let _ = operator.begin_drain();
    let joined = client_thread.0.take().unwrap().join();
    if let Some(holder) = holder { holder.finish(); }
    let active = operator.active_connections();
    let no_leaks = server.diagnostics().find_leaked_obligations().is_empty();
    let shutdown = server.shutdown_timeout(Duration::from_secs(3));
    joined.expect("membership client panicked");
    let report = result.expect("service deadline").expect("service exit");
    let expected = if matches!(case, Case::Lifecycle) { 7 } else { 1 };
    assert_eq!(report.accepted_connections(), expected);
    assert_eq!(report.completed_connections(), expected);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(active, 0); assert!(no_leaks); assert!(shutdown);
    let state = controller.lock();
    if matches!(case, Case::Lifecycle) {
        assert_eq!(state.active_leases(&member()), 0); assert_eq!(state.revocations().len(), 1);
    } else {
        assert!(state.stamp(&member()).is_none()); assert!(state.revocations().is_empty());
    }
}

#[test]
fn native_detector_decisions_revoke_old_leases_and_allow_only_fresh_incarnation_grants() {
    for workers in [1, 2] { exercise(Case::Lifecycle, workers); }
}
#[test]
fn admitted_tls_peer_with_wrong_membership_key_cannot_update_controller() { exercise(Case::WrongKey, 1); }
#[test]
fn admitted_tls_observer_cannot_impersonate_membership_authority_even_with_valid_statement() { exercise(Case::WrongPeer, 1); }
#[test]
fn busy_membership_owner_does_not_block_native_service_worker() { exercise(Case::Busy, 1); }
