//! Actual V3 mTLS remote work driven by authenticated local membership ownership.
//! Logical aliases share a fixture certificate; this is not peer-incarnation proof.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::membership::authority::{
    MembershipControlError, MembershipControllerLimits, MembershipFloor, MembershipUpdate,
};
use asupersync::distributed::membership::owned::remote::MembershipRemoteError;
use asupersync::distributed::membership::owned::work::{MembershipWorkError, MembershipWorkTrigger};
use asupersync::distributed::membership::owned::{OwnedLeaseStatus, OwnedMembershipController, OwnedMembershipError};
use asupersync::distributed::membership::{MembershipEvent, MembershipKind};
use asupersync::distributed::remote_owned::{RemoteLeaseSettlement, RemoteRunConfig, RemoteRunTrigger};
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::observability::diagnostics::{Diagnostics, Reason};
use asupersync::remote::{
    ComputationName, NativeRemoteRoute, NativeRemoteRuntime, NativeRemoteRuntimeConfig, NodeId,
    RemoteCap, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteRuntime,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::AuthKey;
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::types::{RegionId, TaskId};
use asupersync::{Cx, Outcome};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

struct Bytes;
impl HasSchema for Bytes {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("membership-remote-bytes.v1") }
}

#[derive(Default)]
struct Witness {
    proxy: Mutex<Option<(RegionId, TaskId)>>,
    parked: AtomicBool,
    cancelled: AtomicBool,
    release: AtomicBool,
    dropped: AtomicBool,
    changed: Notify,
}
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}
struct Stop {
    owner: OwnedMembershipController,
    remote: Arc<NativeRemoteRuntime>,
    service: RemoteComputationServiceHandle,
    witness: Arc<Witness>,
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.witness.release.store(true, Ordering::Release);
        self.witness.changed.notify_waiters();
        self.owner.close();
        let _ = self.remote.begin_drain();
        let _ = self.service.begin_drain();
    }
}

fn config() -> RemoteRunConfig {
    RemoteRunConfig { timeout: Duration::from_secs(20), child: ChildRegionSpec::inherit() }
}

fn decision(node: &str, incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate {
        event: MembershipEvent { node: NodeId::new(node), incarnation, kind }, sequence,
    }.authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}

fn apply(owner: &OwnedMembershipController, incarnation: u64, sequence: u64, kind: MembershipKind) {
    owner.apply_authenticated(&NodeId::new("authority"), &decision("worker", incarnation, sequence, kind)).unwrap();
}

fn holds_lease(diagnostics: &Diagnostics, region: RegionId, holder: TaskId) -> bool {
    diagnostics.explain_region_open(region).reasons.iter().any(|reason| {
        matches!(reason, Reason::ObligationHeld { holder_task, obligation_type, .. }
            if *holder_task == holder && obligation_type == "Lease")
    })
}

#[derive(Clone, Copy, Debug)]
enum Case { Success, Dead, Left, Superseded, Suspect }

fn exercise(workers: usize, case: Case) {
    let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
    let runtime_handle = runtime.handle();
    let diagnostics = runtime.diagnostics();
    let witness = Arc::new(Witness::default());
    runtime.block_on(async {
        let base = Cx::current().unwrap();
        let owner = OwnedMembershipController::new(
            NodeId::new("authority"), 7, AuthKey::from_seed(42),
            ["worker", "other"].map(|node| MembershipFloor {
                node: NodeId::new(node), incarnation: 0, sequence: 0,
            }).to_vec(),
            MembershipControllerLimits { max_members: 2, max_lease_ids: 16 },
            base.timer_driver().unwrap(),
        ).unwrap();
        apply(&owner, 1, 1, MembershipKind::Alive);
        owner.apply_authenticated(&NodeId::new("authority"), &decision("other", 1, 1, MembershipKind::Alive)).unwrap();

        let mut registry = RemoteComputationRegistry::new();
        registry.register::<Bytes, Bytes, _, _>("echo", |_, invocation| async move {
            Ok(RemoteOutcome::Success(invocation.request().input.data().to_vec()))
        }).unwrap();
        let seen = Arc::clone(&witness);
        registry.register::<Bytes, Bytes, _, _>("wait", move |cx, invocation| {
            let seen = Arc::clone(&seen);
            async move {
                let _retire = Retire(Arc::clone(&seen));
                *seen.proxy.lock() = Some((invocation.request().origin_region, invocation.request().origin_task));
                let mut cancelled = std::pin::pin!(cx.cancelled());
                let mut released = std::pin::pin!(seen.changed.wait_until(|| seen.release.load(Ordering::Acquire)));
                let was_cancelled = poll_fn(|task| {
                    if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(true); }
                    if released.as_mut().poll(task).is_ready() { return Poll::Ready(false); }
                    if !seen.parked.swap(true, Ordering::AcqRel) { seen.changed.notify_waiters(); }
                    Poll::Pending
                }).await;
                if was_cancelled {
                    assert!(cx.checkpoint().is_err());
                    seen.cancelled.store(true, Ordering::Release);
                    seen.changed.notify_waiters();
                    // Withhold actual remote cleanup to prove the new composition
                    // cannot finish merely because membership posted local abort.
                    seen.changed.wait_until(|| seen.release.load(Ordering::Acquire)).await;
                    Ok(RemoteOutcome::Cancelled(cx.cancel_reason().expect("V3 cancellation cause")))
                } else {
                    Ok(RemoteOutcome::Success(b"recovered".to_vec()))
                }
            }
        }).unwrap();
        let certificate = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
        let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
        let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(&certificate).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone()).client_auth(ClientAuth::Required(roots)).build().unwrap();
        let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
        let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate).identity(chain, key)
            .with_certificate_pins(pins.clone()).build().unwrap();
        let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, registry.schema_registry().clone());
        policy.grant_tls_peer(NodeId::new("origin"), pins, ["echo", "wait"]).unwrap();
        let hello = policy.hello_for(NodeId::new("origin"));
        let service = RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new().with_max_connections(Some(4)).with_drain_timeout(Duration::from_secs(3))).await.unwrap();
        let address = service.local_addr().unwrap();
        let operator = service.handle();
        let mut serving = base.spawn(move |cx| async move { service.run(&cx).await }).unwrap();
        let client = RemoteComputationClient::new(address, "localhost", connector,
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(5))).unwrap();
        let remote = Arc::new(NativeRemoteRuntime::with_config(runtime_handle, NodeId::new("origin"), [
            NativeRemoteRoute::new(NodeId::new("worker"), hello.clone(), client.clone()),
            NativeRemoteRoute::new(NodeId::new("other"), hello, client),
        ], NativeRemoteRuntimeConfig::new().with_max_in_flight(4).with_drain_timeout(Duration::from_secs(10))).unwrap());
        let _stop = Stop { owner: owner.clone(), remote: Arc::clone(&remote), service: operator.clone(), witness: Arc::clone(&witness) };
        let cx = base.with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin"))
            .with_default_lease(Duration::from_secs(30)).with_runtime(Arc::clone(&remote) as Arc<dyn RemoteRuntime>));

        if matches!(case, Case::Success) {
            let report = owner.run_remote(&cx, NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"membership-owned-secret".to_vec()), config()).await.unwrap();
            assert!(report.is_success(), "{report:?}");
            assert!(!format!("{report:?}").contains("membership-owned-secret"));
            assert!(matches!(report.work.lease, Ok(OwnedLeaseStatus::Released)));
            let outer_region = report.work.close.as_ref().unwrap().region_id;
            let remote_report = report.work.task.unwrap().unwrap();
            assert_ne!(remote_report.close.as_ref().unwrap().region_id, outer_region);
            assert_ne!(outer_region, cx.region_id());
            assert!(matches!(remote_report.task.unwrap().outcome,
                Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"membership-owned-secret"));
        } else {
            let running_owner = owner.clone();
            let mut running = cx.spawn(move |caller| async move {
                running_owner.run_remote(&caller, NodeId::new("worker"), 1, ComputationName::new("wait"),
                    RemoteInput::empty(), config()).await
            }).unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)))
                .await.expect("remote handler actually reached Pending");
            let (proxy_region, proxy_task) = witness.proxy.lock().expect("actual checked remote proxy IDs");
            asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
                while !holds_lease(&diagnostics, proxy_region, proxy_task) {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            }).await.expect("real checked remote lease before membership transition");
            assert!(!witness.cancelled.load(Ordering::Acquire));
            assert_eq!(remote.active_operations(), 1);

            let kind = match case {
                Case::Dead => MembershipKind::Dead,
                Case::Left => MembershipKind::Left,
                Case::Superseded => MembershipKind::Alive,
                Case::Suspect => MembershipKind::Suspect,
                Case::Success => unreachable!(),
            };
            let incarnation = if matches!(case, Case::Superseded) { 2 } else { 1 };
            apply(&owner, incarnation, 2, kind);
            apply(&owner, incarnation, 2, kind); // Exact duplicate cannot repeat cleanup.
            if matches!(case, Case::Suspect) {
                assert!(!witness.cancelled.load(Ordering::Acquire));
                assert!(running.try_join().unwrap().is_none());
            } else {
                asupersync::time::timeout(cx.now(), Duration::from_secs(3), witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire)))
                    .await.expect("membership revocation forwarded real V3 cancellation");
                assert!(running.try_join().unwrap().is_none(), "local lease retirement must wait for remote cleanup");
                assert!(holds_lease(&diagnostics, proxy_region, proxy_task));
                assert_eq!(remote.active_operations(), 1);
                assert!(!witness.dropped.load(Ordering::Acquire));
            }
            let refused = owner.run_remote(&cx, NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(), config()).await;
            assert!(matches!(refused, Err(MembershipRemoteError::Membership(MembershipWorkError::Lease(
                OwnedMembershipError::Control(MembershipControlError::GrantDenied))))));

            // A different logical member on the same native transport still works.
            // Membership revocation must never drain the entire remote runtime.
            let sibling = owner.run_remote(&cx, NodeId::new("other"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"unrelated".to_vec()), config()).await.unwrap();
            assert!(sibling.is_success(), "{sibling:?}");
            if matches!(case, Case::Suspect) { apply(&owner, 1, 3, MembershipKind::Alive); }
            witness.release.store(true, Ordering::Release);
            witness.changed.notify_waiters();
            let report = asupersync::time::timeout(cx.now(), Duration::from_secs(5), running.join(&cx)).await
                .expect("membership and remote drain completed").expect("typed owner result").expect("admitted membership work");
            assert!(report.work.close.is_ok());
            if matches!(case, Case::Suspect) {
                assert!(report.is_success(), "suspicion must not revoke admitted work: {report:?}");
                assert!(matches!(report.work.lease, Ok(OwnedLeaseStatus::Released)));
                assert!(!witness.cancelled.load(Ordering::Acquire));
            } else {
                assert!(!report.is_success());
                let expected = if matches!(case, Case::Superseded) { OwnedLeaseStatus::Superseded } else { OwnedLeaseStatus::Revoked };
                assert!(matches!(report.work.trigger, MembershipWorkTrigger::LeaseEnded(status) if status == expected));
                assert!(matches!(report.work.lease, Ok(status) if status == expected));
                let remote_report = report.work.task.unwrap().expect("retain remote runner report through body cancellation");
                assert!(matches!(remote_report.trigger, RemoteRunTrigger::Cancelled(_)));
                assert!(remote_report.close.is_ok());
                assert!(remote_report.cancel_error.is_none());
                let reply = remote_report.task.unwrap();
                assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
                assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Cancelled(_))));
            }
            assert!(witness.dropped.load(Ordering::Acquire));
            assert!(!holds_lease(&diagnostics, proxy_region, proxy_task));
        }
        assert!(!cx.is_cancel_requested());
        assert_eq!(owner.live_leases(), 0);
        // Terminal publication can briefly precede native driver retirement.
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
            while remote.active_operations() != 0 {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        }).await.expect("all native request owners retired");
        assert!(remote.close(&cx).await);
        owner.close();
        let _ = operator.begin_drain();
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), serving.join(&cx)).await
            .expect("listener drained").expect("listener task").expect("listener result");
        assert_eq!(operator.active_connections(), 0);
        eprintln!("membership_remote_native workers={workers} case={case:?} remote_active=0 leases=0");
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn authenticated_membership_remote_success_preserves_exact_value_and_both_closes() {
    for workers in [1, 2] { exercise(workers, Case::Success); }
}

#[test]
fn authenticated_membership_revocation_drains_parked_v3_work_and_preserves_sibling() {
    for workers in [1, 2] {
        for case in [Case::Dead, Case::Left, Case::Superseded] { exercise(workers, case); }
    }
}

#[test]
fn authenticated_membership_suspicion_refuses_new_remote_work_without_revoking_live_work() {
    for workers in [1, 2] { exercise(workers, Case::Suspect); }
}
