//! A real mTLS decision stops an executing remote handler's TCP effect and drains
//! its child region. This does not prove general remote-side rollback/quiescence.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::membership::{MembershipEvent, MembershipKind};
use asupersync::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate};
use asupersync::distributed::membership::owned::{OwnedLeaseStatus, OwnedMembershipController};
use asupersync::distributed::membership::owned::work::MembershipWorkTrigger;
use asupersync::distributed::membership::service::{
    MEMBERSHIP_SERVICE_COMPUTATION, MembershipDeliveryError,
    register_owned_membership_service, submit_membership_update,
};
use asupersync::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::observability::diagnostics::Reason;
use asupersync::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationClient, RemoteComputationClientConfig,
    RemoteComputationRegistry, RemoteComputationService, RemoteComputationServiceConfig,
    RemoteComputationServiceHandle, RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy,
    RemoteProtocolVersion, RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse,
    RemoteTaskId, SpawnRequest,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::AuthKey;
use asupersync::sync::Notify;
use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet,
    ClientAuth, PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder};
use asupersync::{Cx, Outcome};
use std::future::{Future, poll_fn};
use std::io::{self, Read};
use std::net::TcpListener;
use std::pin::Pin;
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

const WORK: &str = "test.membership-protected-tcp.v1";
struct WorkSchema;
impl HasSchema for WorkSchema {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("test.membership-protected-tcp.bytes.v1") }
}
fn statement(sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: NodeId::new("worker"), incarnation: 1, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}
fn controller(cx: &Cx) -> OwnedMembershipController {
    let owner = OwnedMembershipController::new(NodeId::new("authority"), 7, AuthKey::from_seed(42),
        vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 16 }, cx.timer_driver().unwrap()).unwrap();
    owner.apply_authenticated(&NodeId::new("authority"), &statement(1, MembershipKind::Alive)).unwrap();
    owner
}
struct Join(Option<thread::JoinHandle<()>>);
impl Join { fn finish(&mut self) { self.0.take().unwrap().join().expect("native peer thread"); } }
impl Drop for Join { fn drop(&mut self) { if let Some(thread) = self.0.take() { let _ = thread.join(); } } }
struct Close(Option<(OwnedMembershipController, RemoteComputationServiceHandle)>);
impl Drop for Close {
    fn drop(&mut self) {
        if let Some((controller, service)) = &self.0 { controller.close(); let _ = service.begin_drain(); }
    }
}
struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }

#[test]
fn mtls_revocation_drains_remote_handler_and_closes_its_actually_parked_tcp_stream() {
    for workers in [1, 2] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let effect_address = listener.local_addr().unwrap();
        let peer_closed = Arc::new(AtomicBool::new(false)); let saw_close = Arc::clone(&peer_closed);
        let mut effect_peer = Join(Some(thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "protected TCP connection never started");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("TCP accept: {error}"),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut greeting = [0; 16]; stream.read_exact(&mut greeting).unwrap();
            assert_eq!(&greeting, b"leased-operation");
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                other => panic!("protected socket did not close after revocation: {other:?}"),
            }
            saw_close.store(true, Ordering::Release);
        })));
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let owner = runtime.block_on(async { controller(&Cx::current().unwrap()) });
        let dropped = Arc::new(AtomicBool::new(false));
        let reported = Arc::new(AtomicBool::new(false));
        let (parked_tx, parked_rx) = mpsc::sync_channel(1);
        let mut registry = RemoteComputationRegistry::new();
        register_owned_membership_service(&mut registry, owner.clone()).unwrap();
        let work_owner = owner.clone(); let body_dropped = Arc::clone(&dropped); let work_reported = Arc::clone(&reported);
        registry.register::<WorkSchema, WorkSchema, _, _>(WORK, move |handler_cx, _invocation| {
            let work_owner = work_owner.clone(); let dropped = Arc::clone(&body_dropped);
            let parked_tx = parked_tx.clone(); let reported = Arc::clone(&work_reported);
            async move {
                let admitting_task = (handler_cx.region_id(), handler_cx.task_id());
                let body_marker = Arc::clone(&dropped);
                let report = work_owner.run_scoped(&handler_cx, &NodeId::new("worker"), 1,
                    Duration::from_secs(15), ChildRegionSpec::inherit(), move |child| async move {
                        let _retire = DropFlag(body_marker);
                        let mut stream = TcpStream::connect(effect_address).await?;
                        stream.write_all(b"leased-operation").await?;
                        let mut cancellation = std::pin::pin!(child.cancelled());
                        let mut response = [0]; let mut buffer = ReadBuf::new(&mut response);
                        let mut sent = false;
                        let result = poll_fn(|task| {
                            if cancellation.as_mut().poll(task).is_ready() {
                                let _ = child.checkpoint();
                                return Poll::Ready(Err(io::Error::from(io::ErrorKind::Interrupted)));
                            }
                            let result = Pin::new(&mut stream).poll_read(task, &mut buffer);
                            if result.is_pending() && !sent {
                                parked_tx.try_send((admitting_task, child.region_id())).unwrap(); sent = true;
                            }
                            result
                        }).await;
                        drop(stream);
                        result
                    }).await.unwrap();
                assert!(matches!(report.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Revoked)));
                assert!(!report.is_success()); assert!(report.close.is_ok());
                assert_eq!(report.task.unwrap().unwrap_err().kind(), io::ErrorKind::Interrupted);
                assert!(dropped.load(Ordering::Acquire));
                assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Revoked)));
                assert!(!handler_cx.is_cancel_requested(), "control must not cancel the invoking remote handler");
                reported.store(true, Ordering::Release);
                // This application response reports retirement, NOT successful work.
                Ok(RemoteOutcome::Success(b"retired-after-drain".to_vec()))
            }
        }).unwrap();
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
        // Test identities share the fixture certificate; each computation grant is explicit.
        policy.grant_tls_peer(NodeId::new("authority"), pins.clone(), [MEMBERSHIP_SERVICE_COMPUTATION]).unwrap();
        policy.grant_tls_peer(NodeId::new("caller"), pins, [WORK]).unwrap();
        let authority_hello = policy.hello_for(NodeId::new("authority"));
        let caller_hello = policy.hello_for(NodeId::new("caller"));
        let service = runtime.block_on(RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new().with_max_connections(Some(4)).with_drain_timeout(Duration::from_secs(5)))).unwrap();
        let address = service.local_addr().unwrap(); let operator = service.handle();
        let config = RemoteComputationClientConfig::new().with_max_attempts(1)
            .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(10));
        let work_client = RemoteComputationClient::new(address, "localhost", connector.clone(), config).unwrap();
        let authority_client = RemoteComputationClient::new(address, "localhost", connector, config).unwrap();
        let caller_cleanup = Close(Some((owner.clone(), operator.clone()))); let completion = Arc::clone(&reported);
        let mut caller = Join(Some(thread::spawn(move || {
            let _cleanup = caller_cleanup;
            let client_runtime = RuntimeBuilder::current_thread().build().unwrap();
            client_runtime.block_on(async {
                let cx = Cx::current().unwrap(); let task = RemoteTaskId::next();
                let request = SpawnRequest {
                    remote_task_id: task, computation: ComputationName::new(WORK), input: RemoteInput::new(Vec::new()),
                    lease: Duration::from_secs(10), idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())),
                    budget: None, origin_node: caller_hello.peer_node().clone(), origin_region: cx.region_id(), origin_task: cx.task_id(),
                };
                let wire = RemoteServiceWireRequest::from_spawn_request(caller_hello, &request).unwrap();
                let response = work_client.call(&cx, &wire).await.unwrap();
                assert!(matches!(response, RemoteServiceWireResponse::Outcome {
                    outcome: RemoteServiceWireOutcome::Success(bytes), ..
                } if bytes == b"retired-after-drain"));
                assert!(completion.load(Ordering::Acquire));
            });
            assert!(client_runtime.shutdown_timeout(Duration::from_secs(3)));
        })));
        let diagnostics = runtime.diagnostics(); let authority_owner = owner.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let failure_close = Close(Some((owner.clone(), operator.clone())));
        let mut authority = Join(Some(thread::spawn(move || {
            // On failure, retire owners so the waiting RPC and effect peer can end.
            // On success, the caller's response owns orderly listener shutdown.
            let mut failure_close = failure_close;
            ready_rx.recv_timeout(Duration::from_secs(13)).expect("runtime verified parked TCP effect and lease");
            let client_runtime = RuntimeBuilder::current_thread().build().unwrap();
            client_runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let mut invalid = statement(2, MembershipKind::Dead); let last = invalid.len() - 1; invalid[last] ^= 1;
                assert!(matches!(submit_membership_update(&cx, &authority_client, &authority_hello, &invalid).await,
                    Err(MembershipDeliveryError::Refused)));
                assert_eq!(authority_owner.live_leases(), 1);
                assert!(!dropped.load(Ordering::Acquire)); assert!(!peer_closed.load(Ordering::Acquire));
                submit_membership_update(&cx, &authority_client, &authority_hello, &statement(2, MembershipKind::Dead)).await.unwrap();
            });
            assert!(client_runtime.shutdown_timeout(Duration::from_secs(3)));
            // Disarm without triggering the controller-close side effect.
            drop(failure_close.0.take());
        })));
        let result = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            // Diagnostics stays on its runtime owner; service polling must
            // continue while the real remote handler reaches its parked read.
            let observe = async {
                let deadline = Instant::now() + Duration::from_secs(8);
                let ((region, holder), _child) = loop {
                    match parked_rx.try_recv() {
                        Ok(ids) => break ids,
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(mpsc::TryRecvError::Disconnected) => panic!("TCP effect stopped before parking"),
                    }
                    assert!(Instant::now() < deadline, "actual TCP read never reached Pending");
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                };
                let deadline = Instant::now() + Duration::from_secs(3);
                while !diagnostics.explain_region_open(region).reasons.iter().any(|reason| {
                    matches!(reason, Reason::ObligationHeld { holder_task, obligation_type, .. }
                        if *holder_task == holder && obligation_type == "Lease")
                }) {
                    assert!(Instant::now() < deadline, "real checked lease was never projected");
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
                ready_tx.try_send(()).expect("authority is waiting for readiness");
            };
            asupersync::time::timeout(cx.now(), Duration::from_secs(25),
                futures_lite::future::zip(observe, service.run(&cx))).await.map(|(_, report)| report)
        });
        owner.close(); let _ = operator.begin_drain();
        authority.finish(); caller.finish(); effect_peer.finish();
        let report = result.expect("service watchdog").expect("service drain");
        assert_eq!(report.accepted_connections(), 3);
        assert!(reported.load(Ordering::Acquire)); assert_eq!(operator.active_connections(), 0);
        assert_eq!(owner.live_leases(), 0);
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    }
}

struct Unblock(Option<mpsc::SyncSender<()>>);
impl Drop for Unblock {
    fn drop(&mut self) { if let Some(sender) = self.0.take() { let _ = sender.try_send(()); } }
}

#[test]
fn revocation_during_real_blocking_descendant_drain_prevents_late_commit() {
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 1).build().unwrap();
    let owner = runtime.block_on(async { controller(&Cx::current().unwrap()) });
    let entered = Arc::new(AtomicBool::new(false)); let changed = Arc::new(Notify::new());
    let retired = Arc::new(AtomicBool::new(false)); let returned = Arc::new(AtomicBool::new(false));
    let (closing_tx, closing_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let updates = owner.clone(); let observed_return = Arc::clone(&returned);
    let mut authority = Join(Some(thread::spawn(move || {
        let _release = Unblock(Some(release_tx)); // Even a failed assertion releases the disk/CPU witness.
        closing_rx.recv_timeout(Duration::from_secs(5)).expect("blocking descendant observed region close");
        assert!(!observed_return.load(Ordering::Acquire), "result escaped before descendant drain");
        updates.apply_authenticated(&NodeId::new("authority"), &statement(2, MembershipKind::Dead)).unwrap();
        assert!(!observed_return.load(Ordering::Acquire));
    })));
    let running = owner.clone(); let body_retired = Arc::clone(&retired);
    let report = runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let mut holder = cx.spawn(move |holder_cx| async move {
            let report = running.run_scoped(&holder_cx, &NodeId::new("worker"), 1,
                Duration::from_secs(15), ChildRegionSpec::inherit(), move |child| async move {
                    let entered_worker = Arc::clone(&entered); let signal = Arc::clone(&changed);
                    let _worker = child.spawn_blocking(move |worker| {
                        let _retire = DropFlag(body_retired);
                        entered_worker.store(true, Ordering::Release); signal.notify_waiters();
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while !worker.is_cancel_requested() {
                            assert!(Instant::now() < deadline, "region close never cancelled blocking descendant");
                            thread::sleep(Duration::from_millis(1));
                        }
                        closing_tx.try_send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).expect("authority released blocking worker");
                        let _ = worker.checkpoint();
                    }).unwrap();
                    changed.wait_until(|| entered.load(Ordering::Acquire)).await;
                    11
                }).await.unwrap();
            returned.store(true, Ordering::Release);
            report
        }).unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(20), holder.join(&cx)).await
            .expect("blocking-drain watchdog").expect("holder result")
    });
    authority.finish();
    assert!(!report.is_success());
    assert!(matches!(report.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Revoked)));
    assert_eq!(report.task.unwrap(), 11); assert!(report.close.is_ok());
    assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Revoked)));
    assert!(retired.load(Ordering::Acquire)); assert_eq!(owner.live_leases(), 0);
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
}

#[test]
fn returned_body_cannot_hide_a_descendant_panic_during_region_close() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let owner = controller(&cx);
        let entered = Arc::new(AtomicBool::new(false)); let changed = Arc::new(Notify::new());
        let mut holder = cx.spawn(move |holder_cx| async move {
            owner.run_scoped(&holder_cx, &NodeId::new("worker"), 1, Duration::from_secs(10),
                ChildRegionSpec::inherit(), move |child| async move {
                    let started = Arc::clone(&entered); let signal = Arc::clone(&changed);
                    let _descendant = child.spawn(move |grandchild| async move {
                        let mut cancelled = std::pin::pin!(grandchild.cancelled());
                        poll_fn(|task| {
                            let result = cancelled.as_mut().poll(task);
                            if result.is_pending() && !started.swap(true, Ordering::AcqRel) { signal.notify_waiters(); }
                            result
                        }).await;
                        let _ = grandchild.checkpoint();
                        panic!("descendant close sentinel");
                    }).unwrap();
                    changed.wait_until(|| entered.load(Ordering::Acquire)).await;
                    17
                }).await.unwrap()
        }).unwrap();
        let report = asupersync::time::timeout(cx.now(), Duration::from_secs(15), holder.join(&cx)).await
            .expect("descendant-drain watchdog").expect("holder result");
        assert!(!report.is_success()); assert_eq!(report.task.unwrap(), 17);
        let receipt = report.close.expect("actual close receipt despite descendant panic");
        assert!(matches!(receipt.outcome, Outcome::Panicked(_))
            || matches!(receipt.cleanup_outcome, Some(Outcome::Panicked(_))));
        assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Dropped)));
        assert!(!cx.is_cancel_requested());
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}
