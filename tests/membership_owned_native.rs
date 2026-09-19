//! Actual mTLS decisions retire leases held by live native runtime tasks.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate};
use asupersync::distributed::membership::owned::{OwnedLeaseStatus, OwnedMembershipController, OwnedMembershipError};
use asupersync::distributed::membership::service::{
    MEMBERSHIP_SERVICE_COMPUTATION, register_owned_membership_service, submit_membership_update,
};
use asupersync::distributed::membership::{MembershipEvent, MembershipKind};
use asupersync::observability::diagnostics::Reason;
use asupersync::remote::{NodeId, RemoteComputationClient, RemoteComputationClientConfig,
    RemoteComputationRegistry, RemoteComputationService, RemoteComputationServiceConfig,
    RemoteComputationServiceHandle, RemotePeerAdmissionPolicy, RemoteProtocolVersion};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::AuthKey;
use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet,
    ClientAuth, PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder};
use asupersync::Cx;
use std::future::{Future, poll_fn};
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

fn statement(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: NodeId::new("worker"), incarnation, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}
fn owner(cx: &Cx) -> OwnedMembershipController {
    OwnedMembershipController::new(NodeId::new("authority"), 7, AuthKey::from_seed(42),
        vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 16 }, cx.timer_driver().unwrap()).unwrap()
}
struct Close {
    controller: OwnedMembershipController,
    service: RemoteComputationServiceHandle,
}
impl Drop for Close {
    fn drop(&mut self) { self.controller.close(); let _ = self.service.begin_drain(); }
}
struct Join(Option<std::thread::JoinHandle<()>>);
impl Drop for Join {
    fn drop(&mut self) { if let Some(thread) = self.0.take() { let _ = thread.join(); } }
}

#[test]
fn mtls_death_wakes_parked_holder_and_settles_its_actual_runtime_lease() {
    for workers in [1, 2] {
        let server = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let controller = server.block_on(async { owner(&Cx::current().unwrap()) });
        controller.apply_authenticated(&NodeId::new("authority"), &statement(1, 1, MembershipKind::Alive)).unwrap();
        let mut registry = RemoteComputationRegistry::new();
        register_owned_membership_service(&mut registry, controller.clone()).unwrap();
        let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
        let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
        let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(&cert).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
            .client_auth(ClientAuth::Required(roots)).build().unwrap();
        let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&cert).unwrap());
        let connector = TlsConnectorBuilder::new().add_root_certificate(&cert).identity(chain, key)
            .with_certificate_pins(pins.clone()).build().unwrap();
        let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
        policy.grant_tls_peer(NodeId::new("authority"), pins, [MEMBERSHIP_SERVICE_COMPUTATION]).unwrap();
        let hello = policy.hello_for(NodeId::new("authority"));
        let service = server.block_on(RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new().with_max_connections(Some(2)).with_drain_timeout(Duration::from_secs(3)))).unwrap();
        let address = service.local_addr().unwrap(); let operator = service.handle();
        let close = Close { controller: controller.clone(), service: operator.clone() };
        let diagnostics = server.diagnostics();
        let (tx, rx) = mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let mut client = Join(Some(std::thread::spawn(move || {
            let _close = close; // A failing client still wakes and retires the owner.
            ready_rx.recv_timeout(Duration::from_secs(10)).expect("runtime verified the parked lease");
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let client = RemoteComputationClient::new(address, "localhost", connector,
                    RemoteComputationClientConfig::new().with_max_attempts(1)
                        .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(3))).unwrap();
                submit_membership_update(&cx, &client, &hello, &statement(1, 2, MembershipKind::Dead)).await.unwrap();
            });
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        })));
        let owned = controller.clone();
        let result = server.block_on(async {
            let cx = Cx::current().unwrap();
            let mut holder = cx.spawn(move |child| async move {
                let guard = owned.try_grant(&child, &NodeId::new("worker"), 1, Duration::from_secs(30)).unwrap();
                let mut reported = false;
                let status = {
                    let mut waiting = std::pin::pin!(guard.ended());
                    poll_fn(|task| {
                        let result = waiting.as_mut().poll(task);
                        if result.is_pending() && !reported {
                            tx.try_send((child.region_id(), child.task_id())).unwrap(); reported = true;
                        }
                        result
                    }).await
                };
                assert!(reported); assert_eq!(status, OwnedLeaseStatus::Revoked);
                assert!(!child.is_cancel_requested(), "membership retirement does not cancel the holder task");
                assert!(matches!(guard.release(), Err(OwnedMembershipError::Ended(OwnedLeaseStatus::Revoked))));
                status
            }).unwrap();
            // Diagnostics can be non-Send with the full feature set. Inspect
            // it on the runtime owner, and send only readiness to the client.
            let deadline = Instant::now() + Duration::from_secs(5);
            let (region, holder_id) = loop {
                match rx.try_recv() {
                    Ok(ids) => break ids,
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => panic!("lease holder stopped before parking"),
                }
                assert!(Instant::now() < deadline, "lease waiter never reached Pending");
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            };
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let held = diagnostics.explain_region_open(region).reasons.iter().any(|reason| {
                    matches!(reason, Reason::ObligationHeld { holder_task, obligation_type, .. }
                        if *holder_task == holder_id && obligation_type == "Lease")
                });
                if held { break; }
                assert!(Instant::now() < deadline, "checked reservation was never projected into the real runtime");
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            ready_tx.try_send(()).expect("mTLS client is waiting for readiness");
            let report = asupersync::time::timeout(cx.now(), Duration::from_secs(12), service.run(&cx)).await;
            controller.close();
            let status = asupersync::time::timeout(cx.now(), Duration::from_secs(3), holder.join(&cx)).await;
            (report, status)
        });
        controller.close(); let _ = operator.begin_drain();
        let client_result = client.0.take().unwrap().join();
        let active = operator.active_connections();
        let leaks = server.diagnostics().find_leaked_obligations();
        let stopped = server.shutdown_timeout(Duration::from_secs(3));
        client_result.expect("mTLS authority client");
        result.0.expect("service deadline").expect("service result");
        assert_eq!(result.1.expect("holder deadline").expect("holder join"), OwnedLeaseStatus::Revoked);
        assert_eq!(active, 0); assert_eq!(controller.live_leases(), 0); assert!(leaks.is_empty()); assert!(stopped);
    }
}

#[test]
fn native_timer_expires_owned_guard_and_driver_shutdown_leaves_no_leaks() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let controller = owner(&cx);
            controller.apply_authenticated(&NodeId::new("authority"), &statement(1, 1, MembershipKind::Alive)).unwrap();
            let running = controller.clone();
            let mut driver = cx.spawn(move |child| async move { running.run(&child).await }).unwrap();
            let owned = controller.clone();
            let parked = Arc::new(AtomicBool::new(false)); let witness = Arc::clone(&parked);
            let mut holder = cx.spawn(move |child| async move {
                let guard = owned.try_grant(&child, &NodeId::new("worker"), 1, Duration::from_millis(100)).unwrap();
                let status = {
                    let mut wait = std::pin::pin!(guard.ended());
                    poll_fn(|task| {
                        let result = wait.as_mut().poll(task);
                        if result.is_pending() { witness.store(true, Ordering::Release); }
                        result
                    }).await
                };
                assert_eq!(status, OwnedLeaseStatus::Expired);
                assert!(matches!(guard.release(), Err(OwnedMembershipError::Ended(OwnedLeaseStatus::Expired))));
                assert!(!child.is_cancel_requested());
            }).unwrap();
            let result = asupersync::time::timeout(cx.now(), Duration::from_secs(5), holder.join(&cx)).await;
            controller.close();
            let drained = asupersync::time::timeout(cx.now(), Duration::from_secs(3), driver.join(&cx)).await;
            result.expect("expiry deadline").expect("holder join");
            drained.expect("driver deadline").expect("driver join").expect("driver result");
            assert!(parked.load(Ordering::Acquire)); assert_eq!(controller.live_leases(), 0);
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn dropping_native_expiry_future_wakes_existing_guards_without_parent_cancellation() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let controller = owner(&cx);
        controller.apply_authenticated(&NodeId::new("authority"), &statement(1, 1, MembershipKind::Alive)).unwrap();
        let guard = controller.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(60)).unwrap();
        let mut driver = Box::pin(controller.run(&cx));
        poll_fn(|task| { assert!(driver.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        drop(driver);
        assert_eq!(guard.ended().await, OwnedLeaseStatus::Closed); drop(guard);
        assert_eq!(controller.live_leases(), 0); assert!(!cx.is_cancel_requested());
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}
