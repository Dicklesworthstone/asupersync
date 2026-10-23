//! Authenticated route eligibility is independent of endpoint discovery.
//! These native tests bind locally authorized generations to fixed TLS clients;
//! authority statements do not themselves attest the peer process incarnation.

use super::*;
use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::membership::authority::{
    MembershipApplied, MembershipControlError, MembershipControllerLimits, MembershipFloor,
    MembershipUpdate,
};
use asupersync::distributed::membership::owned::{OwnedMembershipController, OwnedMembershipError};
use asupersync::distributed::membership::{MembershipEvent, MembershipKind};
use asupersync::distributed::remote_owned::RemoteRunConfig;
use asupersync::remote::{
    NativeRemoteDiscoveryConfig, NativeRemoteDiscoveryDriver, NativeRemoteDiscoveryError,
    RemoteComputationClientError, RemoteError,
};
use asupersync::runtime::{RootDrainOutcome, RuntimeHandle};
use asupersync::security::AuthKey;
use asupersync::service::StaticList;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

const CHARGE: usize = 16 * (4096 + 4) + 256 * 1024;
const WAIT: Duration = Duration::from_secs(5);

fn authority(cx: &Cx) -> OwnedMembershipController {
    OwnedMembershipController::new(
        NodeId::new("authority"),
        7,
        AuthKey::from_seed(42),
        vec![MembershipFloor {
            node: NodeId::new("peer"),
            incarnation: 1,
            sequence: 0,
        }],
        MembershipControllerLimits {
            max_members: 1,
            max_lease_ids: 16,
        },
        cx.timer_driver().unwrap(),
    )
    .unwrap()
}

fn statement(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate {
        event: MembershipEvent {
            node: NodeId::new("peer"),
            incarnation,
            kind,
        },
        sequence,
    }
    .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42))
    .unwrap()
}

fn apply(owner: &OwnedMembershipController, incarnation: u64, sequence: u64, kind: MembershipKind) {
    owner
        .apply_authenticated(
            &NodeId::new("authority"),
            &statement(incarnation, sequence, kind),
        )
        .unwrap();
}

fn refused(cx: &Cx) {
    assert!(matches!(
        spawn_remote(cx, NodeId::new("peer"), ComputationName::new("echo"), RemoteInput::empty()),
        Err(RemoteError::NodeUnreachable(node)) if node == "peer"
    ));
}

async fn echo(cx: &Cx, bytes: &[u8]) {
    let mut task = spawn_remote(
        cx,
        NodeId::new("peer"),
        ComputationName::new("echo"),
        RemoteInput::new(bytes.to_vec()),
    )
    .unwrap();
    assert!(matches!(task.join(cx).await,
        Outcome::Ok(RemoteOutcome::Success(result)) if result == bytes));
}

fn domain(handle: &RuntimeHandle, route: NativeRemoteRoute) -> AdmittedNativeRemoteRuntime {
    AdmittedNativeRemoteRuntime::new(
        handle.clone(),
        NodeId::new("origin"),
        [(
            route,
            NativeRemotePeerAdmissionLimits {
                max_in_flight: 1,
                max_buffer_bytes: CHARGE,
                max_input_bytes: 1024,
            },
        )],
        NativeRemoteAdmissionLimits {
            max_routes: 1,
            max_in_flight: 1,
            max_buffer_bytes: CHARGE,
            max_waiters: 1,
            max_waiters_per_peer: 1,
        },
        NativeRemoteRuntimeConfig::new()
            .with_max_in_flight(1)
            .with_drain_timeout(Duration::from_secs(3)),
    )
    .unwrap()
}

struct Stop {
    owner: OwnedMembershipController,
    native: Vec<Arc<NativeRemoteRuntime>>,
    admitted: Vec<AdmittedNativeRemoteRuntime>,
    services: Vec<RemoteComputationServiceHandle>,
    witness: Arc<Witness>,
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.witness.release();
        self.owner.close();
        for runtime in &self.native {
            let _ = runtime.begin_drain();
        }
        for runtime in &self.admitted {
            runtime.begin_drain();
        }
        for service in &self.services {
            let _ = service.begin_drain();
        }
    }
}

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx, RuntimeHandle) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (sent, received) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("membership-route-fixture".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                for workers in [1, 2] {
                    for sharded in [false, true] {
                        let builder = if workers == 1 {
                            RuntimeBuilder::current_thread()
                        } else {
                            RuntimeBuilder::new().worker_threads(workers)
                        };
                        let runtime = builder
                            .thread_stack_size(16 * 1024 * 1024)
                            .with_sharded_state(sharded)
                            .build()
                            .unwrap();
                        let handle = runtime.handle();
                        runtime.block_on(async {
                            let root = Cx::current().unwrap();
                            let mut task = root.spawn(move |cx| scenario(cx, handle)).unwrap();
                            task.join(&root).await.unwrap();
                        });
                        let report = runtime.shutdown_drained(WAIT);
                        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                        assert_eq!(report.live_tasks, 0);
                        assert_eq!(report.pending_spawns, 0);
                        assert_eq!(report.pending_obligations, 0);
                    }
                }
            }));
            let _ = sent.send(result);
        })
        .unwrap();
    let result = received
        .recv_timeout(Duration::from_secs(90))
        .expect("membership route journey must finish and drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn refuses_unbound_tls_identity(owner: &OwnedMembershipController, route: &NativeRemoteRoute) {
    let cert = Certificate::from_pem(include_bytes!("../fixtures/tls/server.crt"))
        .unwrap()
        .remove(0);
    let second = Certificate::from_pem(include_bytes!("../fixtures/tls/admission_peer.crt"))
        .unwrap()
        .remove(0);
    let pin = CertificatePin::compute_spki_sha256(&cert).unwrap();
    let mut audit_only = CertificatePinSet::new().with_pin(pin.clone());
    audit_only.set_enforce(false);
    let certificate_only =
        CertificatePinSet::new().with_pin(CertificatePin::compute_cert_sha256(&cert).unwrap());
    let rotating = CertificatePinSet::new()
        .with_pin(pin)
        .with_pin(CertificatePin::compute_spki_sha256(&second).unwrap());
    for pins in [
        None,
        Some(audit_only),
        Some(certificate_only),
        Some(rotating),
    ] {
        let mut builder = TlsConnectorBuilder::new()
            .add_root_certificate(&cert)
            .identity(
                CertificateChain::from_pem(include_bytes!("../fixtures/tls/server.crt")).unwrap(),
                PrivateKey::from_pem(include_bytes!("../fixtures/tls/server.key")).unwrap(),
            );
        if let Some(pins) = pins {
            builder = builder.with_certificate_pins(pins);
        }
        let client = RemoteComputationClient::new(
            route.client().bootstrap_endpoints()[0],
            "localhost",
            builder.build().unwrap(),
            route.client().config(),
        )
        .unwrap();
        assert!(matches!(
            NativeRemoteRoute::new(NodeId::new("peer"), route.hello().clone(), client)
                .with_membership(owner.clone(), 1),
            Err(RemoteComputationClientError::InvalidConfig(_))
        ));
    }
}

async fn empty_discovery(cx: &Cx, native: &Arc<NativeRemoteRuntime>) {
    let generation = native.route_generation();
    let driver = NativeRemoteDiscoveryDriver::new(
        Arc::clone(native),
        NodeId::new("peer"),
        Arc::new(StaticList::<SocketAddr>::new(Vec::new())),
        NativeRemoteDiscoveryConfig::new().with_max_consecutive_failures(1),
    )
    .unwrap();
    let error = driver
        .run(cx)
        .await
        .expect_err("legacy empty snapshots remain refused");
    assert!(matches!(
        &error,
        NativeRemoteDiscoveryError::RetryExhausted { .. }
    ));
    assert_eq!(error.report().polls(), 1);
    assert_eq!(error.report().refused_snapshots(), 1);
    assert_eq!(native.route_generation(), generation);
}

#[test]
fn authenticated_route_withdrawal_survives_discovery_and_requires_explicit_rejoin_binding() {
    native(|cx, runtime| async move {
        let owner = authority(&cx);
        let witness = Arc::new(Witness::default());
        let mut old = start_service(
            &cx,
            "peer",
            include_bytes!("../fixtures/tls/server.crt"),
            include_bytes!("../fixtures/tls/server.key"),
            Arc::clone(&witness),
        )
        .await;
        let mut fresh = start_service(
            &cx,
            "peer",
            include_bytes!("../fixtures/tls/admission_peer.crt"),
            include_bytes!("../fixtures/tls/admission_peer.key"),
            Arc::new(Witness::default()),
        )
        .await;
        let bound = old.route.clone().with_membership(owner.clone(), 1).unwrap();
        let native = Arc::new(
            NativeRemoteRuntime::new(runtime.clone(), NodeId::new("origin"), [bound.clone()])
                .unwrap(),
        );
        let legacy = Arc::new(
            NativeRemoteRuntime::new(runtime, NodeId::new("origin"), [old.route.clone()]).unwrap(),
        );
        let _stop = Stop {
            owner: owner.clone(),
            native: vec![Arc::clone(&native), Arc::clone(&legacy)],
            admitted: Vec::new(),
            services: vec![old.operator.clone(), fresh.operator.clone()],
            witness,
        };
        let remote = cx.with_remote_cap(
            RemoteCap::new()
                .with_local_node(NodeId::new("origin"))
                .with_runtime(native.clone()),
        );
        let peer = NodeId::new("peer");

        refuses_unbound_tls_identity(&owner, &old.route);
        assert!(
            native.route(&peer).is_some(),
            "provisioned catalog is not live authority"
        );
        assert!(native.effective_route(&peer).is_none());
        refused(&remote);
        let alive = statement(1, 1, MembershipKind::Alive);
        assert!(matches!(
            owner.apply_authenticated(&NodeId::new("intruder"), &alive),
            Err(OwnedMembershipError::Control(
                MembershipControlError::Authority
            ))
        ));
        let mut forged = alive.clone();
        forged[16] ^= 1;
        assert!(matches!(
            owner.apply_authenticated(&NodeId::new("authority"), &forged),
            Err(OwnedMembershipError::Control(
                MembershipControlError::Authentication
            ))
        ));
        refused(&remote);
        assert_eq!(native.active_operations(), 0);
        assert_eq!(old.operator.active_connections(), 0);

        apply(&owner, 1, 1, MembershipKind::Alive);
        assert!(native.effective_route(&peer).is_some());
        echo(&remote, b"authorized first incarnation").await;
        apply(&owner, 1, 2, MembershipKind::Suspect);
        assert!(native.effective_route(&peer).is_none());
        refused(&remote);
        let snapshot = StaticList::new(old.route.client().bootstrap_endpoints().to_vec());
        native
            .replace_routes([bound.with_discovered_endpoints(&snapshot).unwrap()])
            .unwrap();
        assert!(
            native.effective_route(&peer).is_none(),
            "endpoint refresh must retain the gate"
        );
        refused(&remote);
        apply(&owner, 1, 3, MembershipKind::Alive);
        echo(&remote, b"authenticated suspicion recovery").await;

        apply(&owner, 1, 4, MembershipKind::Dead);
        assert_eq!(
            owner
                .apply_authenticated(
                    &NodeId::new("authority"),
                    &statement(1, 4, MembershipKind::Dead)
                )
                .unwrap(),
            MembershipApplied::Duplicate
        );
        empty_discovery(&remote, &native).await;
        empty_discovery(&remote, &legacy).await;
        assert!(native.route(&peer).is_some());
        assert!(
            native.effective_route(&peer).is_none(),
            "an empty discovery poll cannot preserve revoked route authority"
        );
        assert!(
            legacy.effective_route(&peer).is_some(),
            "unbound routes preserve their documented last-known-good behavior"
        );
        refused(&remote);
        assert!(matches!(
            owner.apply_authenticated(
                &NodeId::new("authority"),
                &statement(1, 5, MembershipKind::Alive)
            ),
            Err(OwnedMembershipError::Control(
                MembershipControlError::Terminal
            ))
        ));

        apply(&owner, 2, 5, MembershipKind::Alive);
        assert!(
            native.effective_route(&peer).is_none(),
            "a fresh membership generation must not reuse the old bound identity"
        );
        refused(&remote);
        let rebound = fresh
            .route
            .clone()
            .with_membership(owner.clone(), 2)
            .unwrap();
        native.replace_routes([rebound.clone()]).unwrap();
        echo(&remote, b"explicitly provisioned fresh identity").await;
        assert!(matches!(
            owner.apply_authenticated(
                &NodeId::new("authority"),
                &statement(1, 6, MembershipKind::Dead)
            ),
            Err(OwnedMembershipError::Control(MembershipControlError::Stale))
        ));
        assert!(native.effective_route(&peer).is_some());

        // A discovery endpoint can change reachability, never the bound TLS
        // identity. Direct it at the old server, then restore the healthy route.
        native
            .replace_routes([rebound
                .with_bootstrap_endpoints(old.route.client().bootstrap_endpoints().iter().copied())
                .unwrap()])
            .unwrap();
        let mut wrong_peer = spawn_remote(
            &remote,
            peer.clone(),
            ComputationName::new("echo"),
            RemoteInput::empty(),
        )
        .unwrap();
        assert!(matches!(wrong_peer.join(&remote).await, Outcome::Err(_)));
        native
            .replace_routes([fresh
                .route
                .clone()
                .with_membership(owner.clone(), 2)
                .unwrap()])
            .unwrap();
        echo(&remote, b"healthy after wrong-identity refusal").await;

        owner.close();
        assert_eq!(owner.stamp(&peer).unwrap().kind, MembershipKind::Alive);
        assert!(
            native.effective_route(&peer).is_none(),
            "closed policy must not treat its retained Alive stamp as permission"
        );
        refused(&remote);
        let legacy_cx = remote.with_remote_cap(
            RemoteCap::new()
                .with_local_node(NodeId::new("origin"))
                .with_runtime(legacy.clone()),
        );
        echo(&legacy_cx, b"unbound compatibility route").await;
        assert!(native.close(&legacy_cx).await);
        assert!(legacy.close(&legacy_cx).await);
        let _ = old.operator.begin_drain();
        let _ = fresh.operator.begin_drain();
        assert!(old.task.join(&legacy_cx).await.unwrap().is_ok());
        assert!(fresh.task.join(&legacy_cx).await.unwrap().is_ok());
        assert_eq!(old.operator.active_connections(), 0);
        assert_eq!(fresh.operator.active_connections(), 0);
        assert_eq!(native.active_operations(), 0);
        assert_eq!(owner.live_leases(), 0);
    });
}

#[test]
fn membership_withdrawal_rechecks_waiting_reservations_and_preserves_native_drain_credit() {
    native(|cx, runtime| async move {
        let owner = authority(&cx);
        apply(&owner, 1, 1, MembershipKind::Alive);
        let witness = Arc::new(Witness::default());
        let mut service = start_service(
            &cx,
            "peer",
            include_bytes!("../fixtures/tls/server.crt"),
            include_bytes!("../fixtures/tls/server.key"),
            Arc::clone(&witness),
        )
        .await;
        let admitted = domain(
            &runtime,
            service
                .route
                .clone()
                .with_membership(owner.clone(), 1)
                .unwrap(),
        );
        let mut stop = Stop {
            owner: owner.clone(),
            native: Vec::new(),
            admitted: vec![admitted.clone()],
            services: vec![service.operator.clone()],
            witness: Arc::clone(&witness),
        };
        let peer = NodeId::new("peer");
        let echo = ComputationName::new("echo");
        let lease = Duration::from_secs(3);

        let issued = admitted.reserve(&cx, &peer, 0, WAIT).await.unwrap();
        let mut queued = Box::pin(admitted.reserve(&cx, &peer, 0, WAIT));
        poll_fn(|task| {
            assert!(queued.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(admitted.usage().waiters, 1);
        apply(&owner, 1, 2, MembershipKind::Suspect);
        assert!(matches!(
            issued.commit(&cx, &echo, &[], lease),
            Err(NativeRemoteAdmissionError::Remote(
                RemoteError::NodeUnreachable(_)
            ))
        ));
        let issued_after_wait = queued.await.unwrap();
        assert!(matches!(
            issued_after_wait.commit(&cx, &echo, &[], lease),
            Err(NativeRemoteAdmissionError::Remote(
                RemoteError::NodeUnreachable(_)
            ))
        ));
        assert_eq!(admitted.usage().in_flight, 0);
        assert_eq!(admitted.usage().buffer_bytes, 0);
        assert_eq!(admitted.usage().waiters, 0);
        assert_eq!(service.operator.active_connections(), 0);

        apply(&owner, 1, 3, MembershipKind::Alive);
        let mut active = admitted
            .reserve(&cx, &peer, 0, WAIT)
            .await
            .unwrap()
            .commit(&cx, &ComputationName::new("wait"), &[], lease)
            .unwrap();
        eventually(&cx, || {
            witness.parked.load(Ordering::Acquire) && active.state() == RemoteTaskState::Running
        })
        .await;
        let mut queued = Box::pin(admitted.reserve(&cx, &peer, 0, WAIT));
        poll_fn(|task| {
            assert!(queued.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        apply(&owner, 1, 4, MembershipKind::Dead);
        assert!(
            !witness.cancelled.load(Ordering::Acquire),
            "route eligibility alone must not replace caller-owned cancellation"
        );

        let reason = CancelReason::user("withdrawn route still drains its admitted client");
        let mut closing = Box::pin(active.close(&cx, &reason));
        poll_fn(|task| {
            assert!(closing.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        eventually(&cx, || witness.cancelled.load(Ordering::Acquire)).await;
        assert!(!witness.retired.load(Ordering::Acquire));
        assert_eq!(admitted.usage().buffer_bytes, CHARGE);
        assert_eq!(admitted.usage().in_flight, 1);
        assert_eq!(admitted.usage().waiters, 1);
        witness.release();
        assert!(matches!(closing.await.unwrap(),
            Outcome::Ok(RemoteOutcome::Cancelled(received)) if received == reason));
        let after_drain = queued.await.unwrap();
        assert!(matches!(
            after_drain.commit(&cx, &echo, &[], lease),
            Err(NativeRemoteAdmissionError::Remote(
                RemoteError::NodeUnreachable(_)
            ))
        ));
        eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
        assert!(witness.retired.load(Ordering::Acquire));

        apply(&owner, 2, 5, MembershipKind::Alive);
        let old_generation = admitted.reserve(&cx, &peer, 0, WAIT).await.unwrap();
        assert!(matches!(
            old_generation.commit(&cx, &echo, &[], lease),
            Err(NativeRemoteAdmissionError::Remote(
                RemoteError::NodeUnreachable(_)
            ))
        ));
        assert!(admitted.close(&cx).await.unwrap());
        let fresh = domain(
            &runtime,
            service
                .route
                .clone()
                .with_membership(owner.clone(), 2)
                .unwrap(),
        );
        stop.admitted.push(fresh.clone());
        let report = fresh
            .reserve(&cx, &peer, 5, WAIT)
            .await
            .unwrap()
            .run_owned(
                &cx,
                &echo,
                b"fresh",
                lease,
                RemoteRunConfig {
                    timeout: Duration::from_secs(10),
                    child: ChildRegionSpec::inherit(),
                },
            )
            .await
            .unwrap();
        assert!(report.is_success(), "{report:?}");
        assert!(matches!(report.task.as_ref().unwrap().outcome,
            Outcome::Ok(RemoteOutcome::Success(ref bytes)) if bytes == b"fresh"));
        eventually(&cx, || fresh.usage().buffer_bytes == 0).await;
        let pending_close = fresh.reserve(&cx, &peer, 0, WAIT).await.unwrap();
        owner.close();
        assert!(matches!(
            pending_close.commit(&cx, &echo, &[], lease),
            Err(NativeRemoteAdmissionError::Remote(
                RemoteError::NodeUnreachable(_)
            ))
        ));
        assert!(fresh.close(&cx).await.unwrap());
        assert_eq!(fresh.usage().in_flight, 0);
        assert_eq!(fresh.usage().buffer_bytes, 0);
        assert_eq!(fresh.usage().waiters, 0);
        assert_eq!(owner.live_leases(), 0);
        let _ = service.operator.begin_drain();
        assert!(service.task.join(&cx).await.unwrap().is_ok());
        assert_eq!(service.operator.active_connections(), 0);
    });
}
