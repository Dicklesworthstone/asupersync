//! Executable ownership, conflict, replay and wire-boundary journeys.
//! Native authenticated transport coverage lives in tests/global_names_native.rs.

use super::*;
use crate::channel::mpsc;
use crate::distributed::membership::{
    MembershipEvent,
    authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate},
};
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::TaskHandle;
use crate::security::AuthKey;
use crate::types::{Budget, CancelReason};
use std::task::{Context, Waker};

const AUTHORITY: &str = "name-authority";
const EPOCH: u64 = 7;

fn decision(
    membership: &OwnedMembershipController, node: &str, incarnation: u64,
    sequence: u64, kind: MembershipKind,
) {
    let update = MembershipUpdate {
        event: MembershipEvent { node: NodeId::new(node), incarnation, kind }, sequence,
    }.authenticated_bytes(&NodeId::new(AUTHORITY), EPOCH, &AuthKey::from_seed(61)).unwrap();
    membership.apply_authenticated(&NodeId::new(AUTHORITY), &update).unwrap();
}

fn provision(
    cx: &Cx, node: &str, peers: &[&str], limit: usize,
) -> (GlobalNameRegistry, OwnedMembershipController) {
    let mut nodes = vec![NodeId::new(node)];
    nodes.extend(peers.iter().map(|peer| NodeId::new(*peer)));
    let membership = OwnedMembershipController::new(
        NodeId::new(AUTHORITY), EPOCH, AuthKey::from_seed(61),
        nodes.iter().map(|node| MembershipFloor { node: node.clone(), incarnation: 0, sequence: 0 }).collect(),
        MembershipControllerLimits { max_members: nodes.len(), max_lease_ids: 1024 },
        cx.timer_driver().expect("lab timer capability"),
    ).unwrap();
    for node in &nodes { decision(&membership, node.as_str(), 1, 1, MembershipKind::Alive); }
    let config = GlobalNameConfig::new(limit, 8, Duration::from_millis(1)).unwrap()
        .with_registration_timeout(Duration::from_millis(5)).unwrap();
    let registry = GlobalNameRegistry::new(
        NodeId::new(node), 1, peers.iter().map(|peer| NodeId::new(*peer)), membership.clone(), config,
    ).unwrap();
    (registry, membership)
}

async fn start(cx: &Cx, registry: &GlobalNameRegistry) -> TaskHandle<Result<GlobalNameRunReport, GlobalNameError>> {
    let driven = registry.clone();
    let task = cx.spawn(move |driver_cx| async move { driven.run(&driver_cx).await }).unwrap();
    registry.wait_running(cx).await.unwrap();
    task
}

async fn stop(
    cx: &Cx, registry: &GlobalNameRegistry, mut task: TaskHandle<Result<GlobalNameRunReport, GlobalNameError>>,
) -> GlobalNameRunReport {
    registry.request_shutdown();
    task.join(cx).await.expect("registry task returned its actual result").expect("graceful registry drain")
}

fn run_case<F, Fut>(seed: u64, factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    crate::test_utils::init_test_logging();
    let mut config = LabConfig::new(seed).max_steps(200_000);
    config.auto_advance_time = true;
    let mut lab = LabRuntime::new(config);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("registered global-name test parent")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_quiescent();
    assert!(join.try_join().unwrap().is_some(), "global-name journey must finish with virtual timers");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
    let gateway = lab.state.obligation_gateway().unwrap();
    assert_eq!(gateway.mailbox().stats().leaked, 0);
    assert_eq!(gateway.mailbox().open_tickets(), 0);
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::user("name test complete"), None).into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
}

fn remote_catalog(owner: &str, incarnation: u64, sequence: u64, names: &[(&str, u64, &str)]) -> Vec<u8> {
    let names = names.iter().map(|(name, registration, computation)| {
        ((*name).to_owned(), GlobalNameTarget {
            node: NodeId::new(owner), incarnation, registration: *registration, computation: (*computation).to_owned(),
        })
    }).collect();
    wire::encode_snapshot(incarnation, sequence, &names).unwrap()
}

async fn await_signal(signal: &Signal) -> Arc<GlobalNameRetirement> {
    signal.changed.wait_until(|| matches!(*signal.status.lock(), GlobalNameLeaseStatus::Retired(_))).await;
    match &*signal.status.lock() {
        GlobalNameLeaseStatus::Retired(retirement) => Arc::clone(retirement),
        _ => unreachable!("terminal signal"),
    }
}

#[test]
fn bounds_and_unwired_context_fail_closed() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<GlobalNameRegistry>();
    send_sync::<GlobalNameLease>();
    assert!(GlobalNameConfig::new(0, 1, Duration::from_millis(1)).is_err());
    assert!(GlobalNameConfig::new(1, 1025, Duration::from_millis(1)).is_err());
    assert!(GlobalNameConfig::new(1, 1, Duration::ZERO).is_err());
    assert!(GlobalNameConfig::new(1, 1, Duration::from_secs(61)).is_err());
    assert!(GlobalNameConfig::new(1, 1, Duration::from_secs(1)).unwrap()
        .with_registration_timeout(Duration::ZERO).is_err());
    run_case(0x674e_0001, |cx| async move {
        let (registry, _) = provision(&cx, "local", &[], 1);
        let detached = Cx::for_testing();
        let mut invalid = Box::pin(registry.run(&detached));
        assert!(matches!(invalid.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(GlobalNameError::Runtime))));
        drop(invalid);
        assert!(matches!(registry.whereis_global(&cx, "name"), Err(GlobalNameError::NotRunning)));
        let driver = start(&cx, &registry).await;
        assert!(matches!(registry.whereis_global(&Cx::for_testing(), "name"), Err(GlobalNameError::Runtime)));
        assert!(matches!(registry.register_global(&cx, "  ", "work").await, Err(GlobalNameError::Format)));
        assert!(registry.whereis_global(&cx, "name").unwrap().is_none());
        assert_eq!(stop(&cx, &registry, driver).await.retired, 0);
    });
}

#[test]
fn unpublished_admission_is_bounded_and_abandonment_drains_before_credit_reuse() {
    for ready in [false, true] {
        run_case(0x674e_0002 + u64::from(ready), move |cx| async move {
            let (registry, _) = provision(&cx, "local", &[], 1);
            let driver = start(&cx, &registry).await;
            let mut registering = Box::pin(registry.register_global(&cx, "job", "work"));
            poll_fn(|task| {
                assert!(registering.as_mut().poll(task).is_pending(), "registration really queued");
                Poll::Ready(())
            }).await;
            let (request, signal) = {
                let state = registry.shared.state.lock();
                let entry = state.locals.get("job").expect("bounded admission slot retained");
                assert!(!entry.published());
                (Arc::clone(&entry.request), Arc::clone(&entry.signal))
            };
            if ready {
                request.changed.wait_until(|| request.reply.lock().value.is_some()).await;
                let state = registry.shared.state.lock();
                assert!(state.locals["job"].group.is_some(), "driver owns actual child group before actor joins");
            }
            assert!(registry.whereis_global(&cx, "job").unwrap().is_none());
            let snapshot = wire::decode_snapshot(registry.local_node(), &registry.snapshot(&cx).unwrap(), 1).unwrap();
            assert!(snapshot.names.is_empty());
            assert!(matches!(registry.register_global(&cx, "other", "work").await, Err(GlobalNameError::Capacity)));
            drop(registering);
            let retirement = await_signal(&signal).await;
            assert_eq!(retirement.reason, GlobalNameEndReason::Released);
            if ready { assert!(retirement.is_drained()); } else { assert!(retirement.exit.is_none()); }
            registry.shared.changed.wait_until(|| registry.shared.state.lock().draining == 0).await;
            let lease = registry.register_global(&cx, "job", "work").await.unwrap();
            assert!(registry.whereis_global(&cx, "job").unwrap().unwrap().local_owner);
            assert!(lease.release(&cx).await.unwrap().is_drained());
            assert_eq!(stop(&cx, &registry, driver).await.close_failures, 0);
        });
    }
}

#[test]
fn stalled_pending_registration_expires_without_publishing_a_name() {
    run_case(0x674e_0004, |cx| async move {
        let (registry, _) = provision(&cx, "local", &[], 1);
        let driver = start(&cx, &registry).await;
        let mut registering = Box::pin(registry.register_global(&cx, "pending", "work"));
        poll_fn(|task| {
            assert!(registering.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        let signal = Arc::clone(&registry.shared.state.lock().locals["pending"].signal);
        let retirement = await_signal(&signal).await;
        assert_eq!(retirement.reason, GlobalNameEndReason::AdmissionExpired);
        assert!(retirement.is_drained(), "unclaimed real group still closes through the driver");
        assert!(registry.whereis_global(&cx, "pending").unwrap().is_none());
        assert!(matches!(registering.await, Err(GlobalNameError::AdmissionExpired)));
        registry.shared.changed.wait_until(|| registry.shared.state.lock().draining == 0).await;
        let lease = registry.register_global(&cx, "replacement", "work").await.unwrap();
        assert!(lease.release(&cx).await.unwrap().is_drained());
        assert_eq!(stop(&cx, &registry, driver).await.close_failures, 0);
    });
}

#[test]
fn actor_terminal_down_retires_a_moved_handle_without_a_child_region_cycle() {
    for seed in [0x674e_0005, 0x674e_0006] {
        run_case(seed, |cx| async move {
            let (registry, _) = provision(&cx, "local", &[], 2);
            let driver = start(&cx, &registry).await;
            let (send_lease, mut receive_lease) = mpsc::channel(1);
            let (finish_actor, mut finished) = mpsc::channel(1);
            let actor_registry = registry.clone();
            let mut actor = cx.spawn(move |actor_cx| async move {
                let lease = actor_registry.register_global(&actor_cx, "actor", "actor.work").await.unwrap();
                send_lease.send(&actor_cx, (actor_cx.task_id(), lease)).await.unwrap();
                finished.recv(&actor_cx).await.unwrap();
            }).unwrap();
            let (actor_id, lease) = receive_lease.recv(&cx).await.unwrap();
            {
                let state = registry.shared.state.lock();
                let entry = &state.locals["actor"];
                assert_eq!(entry.member.as_ref().unwrap().id().task(), actor_id);
                assert_ne!(state.driver_task, Some(actor_id));
                assert!(entry.group.is_some());
            }
            let view = registry.whereis_global(&cx, "actor").unwrap().unwrap();
            assert_eq!(view.target, *lease.target());
            assert_eq!(view.target.computation(), "actor.work");
            finish_actor.send(&cx, ()).await.unwrap();
            actor.join(&cx).await.expect("actor finishes while the moved lease remains alive");
            let retirement = lease.ended().await;
            assert_eq!(retirement.reason, GlobalNameEndReason::OwnerDown);
            assert!(retirement.is_drained());
            assert!(registry.whereis_global(&cx, "actor").unwrap().is_none());
            let report = stop(&cx, &registry, driver).await;
            assert_eq!((report.owner_down, report.close_failures), (1, 0));
        });
    }
}

#[test]
fn deterministic_conflict_aborts_the_actual_lease_and_old_snapshots_cannot_resurrect_it() {
    run_case(0x674e_0007, |cx| async move {
        let (registry, _) = provision(&cx, "z", &["a"], 2);
        let driver = start(&cx, &registry).await;
        let lease = registry.register_global(&cx, "singleton", "local.work").await.unwrap();
        let old_generation = lease.target().registration();
        let before = wire::decode_snapshot(registry.local_node(), &registry.snapshot(&cx).unwrap(), 2).unwrap();
        let competing = remote_catalog("a", 1, 7, &[("singleton", 4, "peer.work")]);
        registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &competing).unwrap();
        let winner = registry.whereis_global(&cx, "singleton").unwrap().unwrap();
        assert_eq!(winner.target.node(), &NodeId::new("a"));
        assert!(!winner.local_owner);
        assert!(matches!(registry.snapshot(&cx), Err(GlobalNameError::PendingRetirement)));
        let retirement = lease.ended().await;
        assert_eq!(retirement.reason, GlobalNameEndReason::Conflict(winner.target.clone()));
        assert!(retirement.is_drained());
        let report = retirement.exit.as_ref().unwrap().task_outcome.as_ref().unwrap();
        assert_eq!((report.joined, report.down, report.settlement_failures), (1, 1, 0));
        let withdrawn = wire::decode_snapshot(registry.local_node(), &registry.snapshot(&cx).unwrap(), 2).unwrap();
        assert!(withdrawn.names.is_empty());
        assert!(withdrawn.sequence > before.sequence);
        let empty = remote_catalog("a", 1, 8, &[]);
        let receipt = registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &empty).unwrap();
        assert_eq!(receipt.sequence, 8);
        registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &empty).unwrap();
        assert!(matches!(registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &competing), Err(GlobalNameError::Stale)));
        let equivocation = remote_catalog("a", 1, 8, &[("singleton", 5, "different")]);
        assert!(matches!(registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &equivocation),
            Err(GlobalNameError::SequenceConflict)));
        assert!(registry.whereis_global(&cx, "singleton").unwrap().is_none());
        let replacement = registry.register_global(&cx, "singleton", "local.new").await.unwrap();
        assert!(replacement.target().registration() > old_generation);
        lease.request_release();
        assert_eq!(registry.whereis_global(&cx, "singleton").unwrap().unwrap().target, *replacement.target());
        assert!(replacement.release(&cx).await.unwrap().is_drained());
        assert_eq!(stop(&cx, &registry, driver).await.conflicts, 1);
    });
}

#[test]
fn suspicion_is_visible_and_terminal_membership_or_reincarnation_revokes_cached_names() {
    for reverse in [false, true] {
        run_case(0x674e_0008 + u64::from(reverse), move |cx| async move {
            let (registry, membership) = provision(&cx, "z", &["a", "c"], 2);
            let driver = start(&cx, &registry).await;
            let a = remote_catalog("a", 1, 2, &[("shared", 1, "a.work")]);
            let c = remote_catalog("c", 1, 9, &[("shared", 2, "c.work")]);
            let updates = if reverse { [("c", &c), ("a", &a)] } else { [("a", &a), ("c", &c)] };
            for (node, bytes) in updates {
                registry.apply_authenticated_snapshot(&cx, &NodeId::new(node), bytes).unwrap();
            }
            assert_eq!(registry.whereis_global(&cx, "shared").unwrap().unwrap().target.node(), &NodeId::new("a"));
            assert!(matches!(registry.apply_authenticated_snapshot(&cx, &NodeId::new("unknown"), &a), Err(GlobalNameError::Authority)));
            decision(&membership, "a", 1, 2, MembershipKind::Suspect);
            let suspect = registry.whereis_global(&cx, "shared").unwrap().unwrap();
            assert_eq!(suspect.target.node(), &NodeId::new("a"));
            assert!(suspect.owner_suspect);
            assert!(matches!(registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &a), Err(GlobalNameError::Authority)));
            decision(&membership, "a", 1, 3, MembershipKind::Dead);
            assert_eq!(registry.whereis_global(&cx, "shared").unwrap().unwrap().target.node(), &NodeId::new("c"));
            decision(&membership, "c", 1, 2, MembershipKind::Left);
            assert!(registry.whereis_global(&cx, "shared").unwrap().is_none());
            let newer = remote_catalog("a", 2, 1, &[("shared", 1, "a.restarted")]);
            assert!(matches!(registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &newer), Err(GlobalNameError::Authority)));
            decision(&membership, "a", 2, 4, MembershipKind::Alive);
            assert!(registry.whereis_global(&cx, "shared").unwrap().is_none(), "new incarnation does not revive cached old names");
            registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &newer).unwrap();
            let view = registry.whereis_global(&cx, "shared").unwrap().unwrap();
            assert_eq!((view.target.incarnation(), view.target.computation()), (2, "a.restarted"));
            assert!(!view.owner_suspect);
            assert!(matches!(registry.apply_authenticated_snapshot(&cx, &NodeId::new("a"), &a), Err(GlobalNameError::Authority)));
            assert_eq!(stop(&cx, &registry, driver).await.retired, 0);
        });
    }
}

#[test]
fn local_suspicion_retains_the_lease_but_death_or_authority_close_drains_it() {
    for close in [false, true] {
        run_case(0x674e_0010 + u64::from(close), move |cx| async move {
            let (registry, membership) = provision(&cx, "local", &[], 2);
            let driver = start(&cx, &registry).await;
            let lease = registry.register_global(&cx, "existing", "work").await.unwrap();
            decision(&membership, "local", 1, 2, MembershipKind::Suspect);
            let view = registry.whereis_global(&cx, "existing").unwrap().unwrap();
            assert!(view.local_owner && view.owner_suspect);
            assert!(matches!(registry.register_global(&cx, "new", "work").await, Err(GlobalNameError::Authority)));
            assert!(matches!(lease.status(), GlobalNameLeaseStatus::Active));
            if close { membership.close(); }
            else { decision(&membership, "local", 1, 3, MembershipKind::Dead); }
            assert!(registry.whereis_global(&cx, "existing").unwrap().is_none());
            let retirement = lease.ended().await;
            assert_eq!(retirement.reason, GlobalNameEndReason::MembershipLost);
            assert!(retirement.is_drained());
            assert_eq!(stop(&cx, &registry, driver).await.close_failures, 0);
        });
    }
}

#[test]
fn abandoning_the_driver_reports_absent_receipt_then_runtime_closes_real_children() {
    run_case(0x674e_0012, |cx| async move {
        let (registry, _) = provision(&cx, "local", &[], 1);
        let (stop_driver, mut stopped) = mpsc::channel(1);
        let driven = registry.clone();
        let mut driver = cx.spawn(move |driver_cx| async move {
            let mut run = Box::pin(driven.run(&driver_cx));
            poll_fn(|task| {
                if matches!(stopped.poll_recv(&driver_cx, task), Poll::Ready(Ok(()))) { return Poll::Ready(()); }
                assert!(run.as_mut().poll(task).is_pending(), "driver remains live until explicit abandonment");
                Poll::Pending
            }).await;
            drop(run);
        }).unwrap();
        registry.wait_running(&cx).await.unwrap();
        let lease = registry.register_global(&cx, "owned", "work").await.unwrap();
        assert!(registry.whereis_global(&cx, "owned").unwrap().is_some());
        stop_driver.send(&cx, ()).await.unwrap();
        let retirement = lease.ended().await;
        assert_eq!(retirement.reason, GlobalNameEndReason::DriverDropped);
        assert!(retirement.exit.is_none());
        assert!(!retirement.is_drained(), "Drop cannot invent a successful close receipt");
        assert!(matches!(registry.whereis_global(&cx, "owned"), Err(GlobalNameError::Closed)));
        driver.join(&cx).await.expect("runtime finishes the abandoned driver's real child barriers");
    });
}

#[test]
fn canonical_codec_refuses_truncation_duplicate_order_limits_and_wrong_receipts() {
    let owner = NodeId::new("owner");
    let bytes = remote_catalog("owner", 1, 2, &[("first", 1, "compute.a"), ("second", 2, "compute.b")]);
    let decoded = wire::decode_snapshot(&owner, &bytes, 2).unwrap();
    assert_eq!(decoded.names.len(), 2);
    for end in 0..bytes.len() {
        assert!(wire::decode_snapshot(&owner, &bytes[..end], 2).is_err(), "every truncation refuses");
    }
    assert!(wire::decode_snapshot(&owner, &bytes, 1).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(wire::decode_snapshot(&owner, &trailing, 2).is_err());
    let first = remote_catalog("owner", 1, 2, &[("first", 1, "compute.a")]);
    let second = remote_catalog("owner", 1, 2, &[("second", 2, "compute.b")]);
    let mut duplicate = bytes[..22].to_vec();
    duplicate.extend_from_slice(&first[22..]);
    duplicate.extend_from_slice(&first[22..]);
    assert!(wire::decode_snapshot(&owner, &duplicate, 2).is_err());
    let mut reversed = bytes[..22].to_vec();
    reversed.extend_from_slice(&second[22..]);
    reversed.extend_from_slice(&first[22..]);
    assert!(wire::decode_snapshot(&owner, &reversed, 2).is_err());
    let mut wrong_count = bytes.clone();
    wrong_count[20..22].copy_from_slice(&1025_u16.to_be_bytes());
    assert!(wire::decode_snapshot(&owner, &wrong_count, 1025).is_err());
    let receipt = wire::snapshot_receipt(&GlobalNameSnapshotReceipt {
        owner: owner.clone(), incarnation: decoded.incarnation, sequence: decoded.sequence, digest: decoded.digest,
    });
    wire::verify_snapshot_receipt(&receipt, &bytes).unwrap();
    let mut changed = receipt.clone();
    changed[51] ^= 1;
    assert!(matches!(wire::verify_snapshot_receipt(&changed, &bytes), Err(GlobalNameError::Receipt)));
    let target = decoded.names.get("first").unwrap();
    let reply = wire::lookup_reply(1, 2, "first", Some(target)).unwrap();
    assert_eq!(wire::decode_lookup_reply(&owner, 1, "first", &reply).unwrap().1.as_ref(), Some(target));
    assert!(matches!(wire::decode_lookup_reply(&owner, 2, "first", &reply), Err(GlobalNameError::Receipt)));
    assert!(matches!(wire::decode_lookup_reply(&owner, 1, "second", &reply), Err(GlobalNameError::Receipt)));
    assert!(wire::lookup_request(&"x".repeat(256), 1).is_err());
    assert!(wire::lookup_request("nul\0name", 1).is_err());
    assert!(wire::lookup_request("name", 0).is_err());
    let empty = wire::lookup_reply(1, 3, "first", None).unwrap();
    assert!(wire::decode_lookup_reply(&owner, 1, "first", &empty).unwrap().1.is_none());
}

#[test]
fn cancellation_of_parked_registration_preserves_the_typed_result_and_drains_admission() {
    run_case(0x674e_0013, |cx| async move {
        let (registry, _) = provision(&cx, "local", &[], 1);
        let driver = start(&cx, &registry).await;
        let (parked, mut witness) = mpsc::channel(1);
        let actor_registry = registry.clone();
        let mut actor = cx.spawn(move |actor_cx| async move {
            let mut registering = Box::pin(actor_registry.register_global(&actor_cx, "cancelled", "work"));
            poll_fn(|task| {
                assert!(registering.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            parked.send(&actor_cx, ()).await.unwrap();
            actor_cx.cancelled().await; // observation alone must not count as acknowledgement
            registering.await
        }).unwrap();
        witness.recv(&cx).await.unwrap();
        assert!(registry.shared.state.lock().locals.contains_key("cancelled"));
        assert!(registry.whereis_global(&cx, "cancelled").unwrap().is_none());
        actor.abort();
        let result = actor.join(&cx).await.expect("register_global acknowledges cancellation before returning its typed result");
        assert!(matches!(result, Err(GlobalNameError::Cancelled)));
        registry.shared.changed.wait_until(|| {
            let state = registry.shared.state.lock();
            state.locals.is_empty() && state.draining == 0
        }).await;
        assert_eq!(stop(&cx, &registry, driver).await.close_failures, 0);
    });
}

#[test]
fn a_masked_cancel_observer_does_not_stop_or_spin_an_idle_driver() {
    run_case(0x674e_0014, |cx| async move {
        let (registry, _) = provision(&cx, "local", &[], 1);
        let driven = registry.clone();
        let mut task = cx.spawn(move |driver_cx| async move {
            let mut run = Box::pin(driven.run(&driver_cx));
            poll_fn(|task| {
                assert!(run.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            driver_cx.cancel_with(crate::types::CancelKind::User, Some("masked driver test"));
            poll_fn(|task| {
                driver_cx.masked(|| {
                    assert!(run.as_mut().poll(task).is_pending(), "mask suppresses delivery without making a busy loop");
                    assert!(driven.is_running());
                });
                Poll::Ready(())
            }).await;
            drop(run);
            assert!(driver_cx.checkpoint().is_err());
        }).unwrap();
        task.join(&cx).await.expect("explicit cancellation acknowledgement preserves the actual child result");
        assert!(!registry.is_running());
    });
}

#[test]
fn opted_in_down_and_conflict_abort_post_real_ledger_aborts_while_public_defaults_commit() {
    for mode in 0..3_u64 {
        run_case(0x674e_0020 + mode, move |cx| async move {
            use crate::spork::process_group::{GroupEventCursor, GroupEventKind};
            let owner = ManagedProcessGroup::<()>::open(
                &cx, GroupName::new("ledger-proof").unwrap(), NodeId::new("local"),
                ManagedProcessGroupConfig::new(1, 1, 1, 4),
            ).await.unwrap();
            if mode == 1 { owner.abort_on_member_down(); }
            let client = owner.client();
            let actor_client = client.clone();
            let (send_guard, mut receive_guard) = mpsc::channel(1);
            let (finish, mut finished) = mpsc::channel(1);
            let mut actor = cx.spawn(move |actor_cx| async move {
                let member = actor_client.join(&actor_cx).await.unwrap();
                send_guard.send(&actor_cx, member).await.unwrap();
                finished.recv(&actor_cx).await.unwrap();
            }).unwrap();
            let member = receive_guard.recv(&cx).await.unwrap();
            assert!(member.is_active(), "actual checked monitored membership has been published");
            let cursor = client.events(&cx, GroupEventCursor::new()).unwrap().batch.next_cursor();
            let mailbox = Arc::clone(cx.obligation_transfer_destination().unwrap().0.mailbox());
            let before = mailbox.stats();
            let exit = if mode == 2 {
                let exit = owner.abort().await;
                finish.send(&cx, ()).await.unwrap();
                actor.join(&cx).await.unwrap();
                exit
            } else {
                finish.send(&cx, ()).await.unwrap();
                actor.join(&cx).await.unwrap();
                let departed = client.next_events(&cx, cursor).await.unwrap();
                assert!(matches!(departed.batch.events()[0].kind(), GroupEventKind::Down(_)));
                owner.shutdown().await
            };
            let report = exit.task_outcome.expect("real controller report");
            assert_eq!((report.joined, report.down, report.settlement_failures), (1, 1, 0));
            assert!(report.state_error.is_none());
            assert!(exit.close.is_ok());
            assert!(!member.is_active());
            let after = mailbox.stats();
            assert_eq!(after.aborted - before.aborted, u64::from(mode != 0),
                "ordinary public DOWN commits; opted-in DOWN and live abort each post one real lease abort");
            assert_eq!(after.leaked, before.leaked);
            assert_eq!(after.refused, before.refused);
        });
    }
}
