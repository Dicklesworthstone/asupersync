//! Native contracts for live node-local process groups.
//!
//! Bead: asupersync-dist-otp-completeness-8y37kz.1.
//! These journeys run on current-thread and two-worker runtimes with unified
//! and sharded state. Pending polls and real monitor receipts establish the
//! causal boundaries; the wall-clock watchdog only bounds a broken test.
//! Replay: rch exec -- env CARGO_TARGET_DIR=target/rch-managed-process-group
//! cargo test --test native_managed_process_group -- --test-threads=1

#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::monitor::DownReason;
use asupersync::remote::NodeId;
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder, TaskHandle};
use asupersync::spork::process_group::{
    BroadcastBackpressurePolicy, GroupEventCursor, GroupEventKind, GroupName,
    ManagedGroupBroadcastReport, ManagedGroupError, ManagedGroupMembership,
    ManagedGroupRecipientStatus, ManagedProcessGroup, ManagedProcessGroupConfig,
    ManagedProcessGroupExit, ProcessGroupClient,
};
use asupersync::types::{CancelKind, CancelReason};
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::mpsc;
use std::task::Poll;
use std::time::Duration;

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                for sharded in [false, true] {
                    let builder = if workers == 1 {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::new().worker_threads(workers)
                    };
                    let runtime = builder.with_sharded_state(sharded).build().unwrap();
                    runtime.block_on(async {
                        let root = Cx::current().unwrap();
                        let mut owner = root.spawn(scenario).unwrap();
                        owner.join(&root).await.unwrap();
                    });
                    let report = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                    assert_eq!(report.live_tasks, 0);
                    assert_eq!(report.pending_spawns, 0);
                    assert_eq!(report.pending_obligations, 0);
                }
            }
        }));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("managed process group must drain every native participant");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

async fn open(cx: &Cx, members: usize, requests: usize, events: usize) -> ManagedProcessGroup<u32> {
    ManagedProcessGroup::open(
        cx,
        GroupName::new("native-workers").unwrap(),
        NodeId::new("local"),
        ManagedProcessGroupConfig::new(members, 1, requests, events),
    )
    .await
    .unwrap()
}

fn closed(exit: ManagedProcessGroupExit) {
    assert!(exit.close.is_ok(), "{:?}", exit.close);
    let report = exit.task_outcome.expect("controller must retire normally");
    assert_eq!(report.settlement_failures, 0);
    assert!(report.state_error.is_none(), "{:?}", report.state_error);
}

// Keep the receiver guard outside its admitted member task. Task death must
// therefore remove membership even though neither Receiver nor guard is dropped.
async fn recruit(
    cx: &Cx,
    client: ProcessGroupClient<u32>,
    panic_on_release: bool,
) -> (ManagedGroupMembership<u32>, TaskHandle<()>, oneshot::Sender<()>) {
    let (registered, mut registration) = oneshot::channel();
    let (release, mut released) = oneshot::channel();
    let task = cx
        .spawn(move |member| async move {
            let membership = client.join(&member).await.unwrap();
            assert!(registered.send_blocking(membership).is_ok());
            released.recv(&member).await.unwrap();
            assert!(!panic_on_release, "native process-group member panic");
        })
        .unwrap();
    let membership = registration.recv(cx).await.unwrap();
    (membership, task, release)
}

type BroadcastResult = Result<ManagedGroupBroadcastReport, ManagedGroupError>;

fn parked_broadcast(
    cx: &Cx,
    client: ProcessGroupClient<u32>,
    message: u32,
) -> (
    TaskHandle<()>,
    oneshot::Receiver<()>,
    oneshot::Receiver<BroadcastResult>,
) {
    let (ready, parked) = oneshot::channel();
    let (completed, completion) = oneshot::channel();
    let task = cx
        .spawn(move |sender| async move {
            let mut ready = Some(ready);
            let mut sending = Box::pin(client.broadcast(
                &sender,
                &message,
                BroadcastBackpressurePolicy::Wait,
            ));
            let result = poll_fn(|task| match sending.as_mut().poll(task) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => {
                    if let Some(ready) = ready.take() {
                        assert!(ready.send_blocking(()).is_ok());
                    }
                    Poll::Pending
                }
            })
            .await;
            assert!(completed.send_blocking(result).is_ok());
        })
        .unwrap();
    (task, parked, completion)
}

async fn actual_member_death(cx: Cx) {
    let owner = open(&cx, 2, 4, 16).await;
    assert_ne!(owner.region_id(), cx.region_id());
    let client = owner.client();
    let (membership, mut member, release) = recruit(&cx, client.clone(), true).await;
    let member_id = membership.id().clone();
    assert_eq!(member_id.task(), member.task_id());
    let cursor = GroupEventCursor::from_next_sequence(membership.joined_event().sequence() + 1);
    let monitor = cx.monitor(&member).await.unwrap();

    release.send_blocking(()).unwrap();
    let down = monitor.down(&cx).await.unwrap();
    assert!(matches!(down.reason, DownReason::Panicked(_)));
    assert!(member.join(&cx).await.is_err());
    // A real monitor has witnessed retirement. Now wait for the group
    // controller to observe that same death without relying on guard Drop.
    let events = client.next_events(&cx, cursor).await.unwrap();
    assert_eq!(events.skipped, 0);
    assert_eq!(events.batch.len(), 1);
    assert_eq!(events.batch.events()[0].member(), &member_id);
    assert!(matches!(
        events.batch.events()[0].kind(),
        GroupEventKind::Down(DownReason::Panicked(_))
    ));
    assert!(!membership.is_active());
    assert!(client.members(&cx).unwrap().is_empty());
    let after = client.events(&cx, events.batch.next_cursor()).unwrap();
    assert!(after.batch.is_empty(), "the same DOWN must not be emitted twice");
    drop(membership);

    let exit = owner.shutdown().await;
    let report = exit.task_outcome.as_ref().unwrap();
    assert_eq!(report.joined, 1);
    assert_eq!(report.down, 1);
    assert_eq!(report.left, 0);
    closed(exit);
}

#[test]
fn actual_task_panic_revokes_a_still_retained_membership_and_settles_its_lease() {
    native(actual_member_death);
}

async fn stale_guard_and_capacity(cx: Cx) {
    let owner = open(&cx, 1, 4, 16).await;
    let client = owner.client();
    let mut old = client.join(&cx).await.unwrap();
    let old_generation = old.generation();
    let left = old.leave(&cx).await.unwrap();
    assert!(matches!(left.kind(), GroupEventKind::Left));
    let mut current = client.join(&cx).await.unwrap();
    assert_eq!(old.id(), current.id());
    assert!(current.generation() > old_generation);
    old.request_leave();
    drop(old);

    // An actual controller round trip checks duplicate identity after stale
    // cleanup was signalled; a synchronous snapshot alone is insufficient.
    assert!(matches!(
        client.join(&cx).await,
        Err(ManagedGroupError::DuplicateMember(_))
    ));
    let other_client = client.clone();
    let mut other = cx
        .spawn(move |other| async move {
            matches!(other_client.join(&other).await, Err(ManagedGroupError::Capacity))
        })
        .unwrap();
    assert!(other.join(&cx).await.unwrap());
    let snapshot = client.members(&cx).unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.members()[0].join_sequence(), current.generation());
    let sent = client.broadcast(&cx, &17, BroadcastBackpressurePolicy::Wait).await.unwrap();
    assert!(sent.is_all_delivered());
    assert_eq!(current.recv(&cx).await.unwrap(), 17);
    current.leave(&cx).await.unwrap();
    closed(owner.shutdown().await);
}

#[test]
fn stale_guard_cannot_revoke_rejoin_and_capacity_counts_actual_live_members() {
    native(stale_guard_and_capacity);
}

async fn cancellation_preserves_delivery_prefix(cx: Cx) {
    let owner = open(&cx, 3, 8, 32).await;
    let client = owner.client();
    let mut first = client.join(&cx).await.unwrap();
    let (mut slow, mut slow_task, slow_release) = recruit(&cx, client.clone(), false).await;
    let (mut last, mut last_task, last_release) = recruit(&cx, client.clone(), false).await;
    let ids = [first.id().clone(), slow.id().clone(), last.id().clone()];
    assert_eq!(
        client.members(&cx).unwrap().member_ids().cloned().collect::<Vec<_>>(),
        ids.to_vec()
    );

    assert!(client.broadcast(&cx, &10, BroadcastBackpressurePolicy::Wait).await.unwrap().is_all_delivered());
    let skipped = client.broadcast(&cx, &11, BroadcastBackpressurePolicy::Skip).await.unwrap();
    assert_eq!(skipped.recipients.len(), 3);
    assert!(skipped.recipients.iter().all(|r| r.status == ManagedGroupRecipientStatus::Skipped));
    let full = client.broadcast(&cx, &12, BroadcastBackpressurePolicy::Error).await.unwrap();
    assert_eq!(full.recipients[0].status, ManagedGroupRecipientStatus::Backpressured);
    assert_eq!(full.recipients[1].status, ManagedGroupRecipientStatus::NotAttempted);
    assert_eq!(full.recipients[2].status, ManagedGroupRecipientStatus::NotAttempted);
    assert_eq!(first.recv(&cx).await.unwrap(), 10);
    assert_eq!(last.recv(&cx).await.unwrap(), 10);

    let (mut sender, mut parked, mut completion) = parked_broadcast(&cx, client.clone(), 20);
    let sender_monitor = cx.monitor(&sender).await.unwrap();
    parked.recv(&cx).await.unwrap();
    // Receiving the prefix proves the pending sender passed the first
    // recipient and is blocked on the still-full middle mailbox.
    assert_eq!(first.recv(&cx).await.unwrap(), 20);
    sender.abort_with_reason(CancelReason::race_loser());
    let result = completion.recv(&cx).await.unwrap().unwrap();
    sender_monitor.down(&cx).await.unwrap();
    let _terminal = sender.join(&cx).await;
    assert_eq!(result.cancellation.as_ref().unwrap().kind, CancelKind::RaceLost);
    assert_eq!(result.recipients.len(), 3);
    assert_eq!(result.recipients[0].member, ids[0]);
    assert_eq!(result.recipients[0].status, ManagedGroupRecipientStatus::Delivered);
    assert_eq!(result.recipients[1].member, ids[1]);
    assert_eq!(result.recipients[1].status, ManagedGroupRecipientStatus::Cancelled);
    assert_eq!(result.recipients[2].member, ids[2]);
    assert_eq!(result.recipients[2].status, ManagedGroupRecipientStatus::NotAttempted);

    let continued = client.broadcast(&cx, &30, BroadcastBackpressurePolicy::Error).await.unwrap();
    assert_eq!(continued.recipients[0].status, ManagedGroupRecipientStatus::Delivered);
    assert_eq!(continued.recipients[1].status, ManagedGroupRecipientStatus::Backpressured);
    assert_eq!(continued.recipients[2].status, ManagedGroupRecipientStatus::NotAttempted);
    assert_eq!(first.recv(&cx).await.unwrap(), 30);
    assert_eq!(slow.recv(&cx).await.unwrap(), 10);
    assert!(client.broadcast(&cx, &31, BroadcastBackpressurePolicy::Wait).await.unwrap().is_all_delivered());
    assert_eq!(first.recv(&cx).await.unwrap(), 31);
    assert_eq!(slow.recv(&cx).await.unwrap(), 31);
    assert_eq!(last.recv(&cx).await.unwrap(), 31, "both stopped suffixes must remain untouched");

    first.leave(&cx).await.unwrap();
    slow.leave(&cx).await.unwrap();
    last.leave(&cx).await.unwrap();
    slow_release.send_blocking(()).unwrap();
    last_release.send_blocking(()).unwrap();
    slow_task.join(&cx).await.unwrap();
    last_task.join(&cx).await.unwrap();
    closed(owner.shutdown().await);
}

#[test]
fn full_mailboxes_report_skip_and_error_and_cancelled_wait_retains_every_recipient() {
    native(cancellation_preserves_delivery_prefix);
}

async fn death_wakes_full_mailbox(cx: Cx) {
    let owner = open(&cx, 1, 4, 16).await;
    let client = owner.client();
    let (membership, mut member, release) = recruit(&cx, client.clone(), false).await;
    let monitor = cx.monitor(&member).await.unwrap();
    assert!(client.broadcast(&cx, &1, BroadcastBackpressurePolicy::Wait).await.unwrap().is_all_delivered());
    let (mut sender, mut parked, mut completion) = parked_broadcast(&cx, client.clone(), 2);
    parked.recv(&cx).await.unwrap();

    // Both this guard's Receiver and the blocked broadcast's Sender remain
    // live. Removing only the controller's Sender cannot wake the reserve.
    release.send_blocking(()).unwrap();
    monitor.down(&cx).await.unwrap();
    member.join(&cx).await.unwrap();
    let report = completion.recv(&cx).await.unwrap().unwrap();
    sender.join(&cx).await.unwrap();
    assert_eq!(report.recipients.len(), 1);
    assert_eq!(report.recipients[0].status, ManagedGroupRecipientStatus::Departed);
    assert!(report.cancellation.is_none());
    assert!(!membership.is_active());
    assert!(client.members(&cx).unwrap().is_empty());
    drop(membership);
    closed(owner.shutdown().await);
}

#[test]
fn member_retirement_wakes_wait_even_with_retained_receiver_and_sender_clones() {
    native(death_wakes_full_mailbox);
}

async fn full_event_credit_cannot_block_leave(cx: Cx) {
    let owner = open(&cx, 1, 1, 8).await;
    let client = owner.client();
    let mut membership = client.join(&cx).await.unwrap();
    let cursor = GroupEventCursor::from_next_sequence(membership.joined_event().sequence() + 1);
    let mut waiting = Box::pin(client.next_events(&cx, cursor));
    poll_fn(|task| {
        assert!(waiting.as_mut().poll(task).is_pending());
        Poll::Ready(())
    })
    .await;

    let left = membership.leave(&cx).await.unwrap();
    let event = waiting.await.unwrap();
    assert_eq!(event.batch.events(), &[left]);
    assert!(client.members(&cx).unwrap().is_empty());
    closed(owner.shutdown().await);
}

#[test]
fn out_of_band_leave_progresses_when_the_only_request_credit_is_a_parked_observer() {
    native(full_event_credit_cannot_block_leave);
}

async fn bounded_event_history(cx: Cx) {
    let owner = open(&cx, 1, 2, 3).await;
    let client = owner.client();
    for _ in 0..8 {
        let mut membership = client.join(&cx).await.unwrap();
        membership.leave(&cx).await.unwrap();
    }
    let events = client.events(&cx, GroupEventCursor::new()).unwrap();
    assert_eq!(events.batch.len(), 3);
    assert_eq!(events.skipped, 13);
    assert_eq!(events.first_retained.next_sequence(), 13);
    assert_eq!(events.batch.next_cursor().next_sequence(), 16);
    assert_eq!(
        events.batch.events().iter().map(|event| event.sequence()).collect::<Vec<_>>(),
        vec![13, 14, 15]
    );
    assert!(client.events(&cx, events.batch.next_cursor()).unwrap().batch.is_empty());
    let exit = owner.shutdown().await;
    assert_eq!(exit.task_outcome.as_ref().unwrap().joined, 8);
    assert_eq!(exit.task_outcome.as_ref().unwrap().left, 8);
    closed(exit);
}

#[test]
fn bounded_history_reports_the_exact_gap_and_cursor_after_churn() {
    native(bounded_event_history);
}

async fn shutdown_and_abandonment(cx: Cx) {
    let owner = open(&cx, 1, 1, 8).await;
    let client = owner.client();
    let membership = client.join(&cx).await.unwrap();
    let cursor = GroupEventCursor::from_next_sequence(membership.joined_event().sequence() + 1);
    let mut waiting = Box::pin(client.next_events(&cx, cursor));
    poll_fn(|task| {
        assert!(waiting.as_mut().poll(task).is_pending());
        Poll::Ready(())
    })
    .await;
    closed(owner.shutdown().await);
    assert!(!membership.is_active());
    assert!(waiting.await.unwrap().closed);
    assert!(!cx.is_cancel_requested(), "member task is outside the group owner region");
    assert!(matches!(client.join(&cx).await, Err(ManagedGroupError::Closed)));
    drop(membership);

    let outer = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    // A child region's Cx is a spawn principal. Admit a real setup task to
    // obtain the checked holder authority required to open a managed group.
    let (prepared, mut preparation) = oneshot::channel();
    let mut setup = outer.cx().spawn(move |setup| async move {
        let owner = open(&setup, 1, 2, 8).await;
        assert!(prepared.send_blocking(owner).is_ok());
    }).unwrap();
    let abandoned = preparation.recv(&cx).await.unwrap();
    setup.join(&cx).await.unwrap();
    let client = abandoned.client();
    let membership = client.join(&cx).await.unwrap();
    let cursor = GroupEventCursor::from_next_sequence(membership.joined_event().sequence() + 1);
    drop(abandoned);
    // Observe the owner's Drop request before enclosing close could mask it.
    let event = client.next_events(&cx, cursor).await.unwrap();
    assert!(event.closed || !membership.is_active());
    outer.close().await.unwrap();
    assert!(!membership.is_active());
    assert!(!cx.is_cancel_requested());
    drop(membership);
}

#[test]
fn shutdown_bypasses_observer_credit_and_owner_drop_keeps_cleanup_region_owned() {
    native(shutdown_and_abandonment);
}
