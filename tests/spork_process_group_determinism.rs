//! Process-group value-layer proofs (8y37kz.1 / [DIST-OTP] process groups).
//!
//! These integration tests link the library in non-test mode (immune to peer
//! `#[cfg(test)]` breakage) and validate the deterministic, synchronous core of
//! `spork::process_group` that backs the future async join/broadcast/monitor
//! surfaces:
//!
//! - **AC3 (determinism):** `members()` snapshot ordering and broadcast
//!   recipient ordering are stable registration order, identical across two
//!   independently-constructed groups fed the same join schedule — even when the
//!   member-id key order disagrees with the join order.
//! - **AC5 (exactly-once events):** a monitor-style [`GroupEventSubscriber`]
//!   observes every join/leave/down transition exactly once, never re-delivers a
//!   committed event, and a stale-batch commit cannot rewind the stream.
//!
//! Scope note: this covers the node-local value layer only. Lease-backed runtime
//! join, real broadcast delivery through mailboxes, and churn/stress remain open
//! on the bead. No broad runtime-correctness or workspace-health claim is made.

#![allow(missing_docs)]

use asupersync::remote::NodeId;
use asupersync::spork::process_group::{
    BroadcastBackpressurePolicy, GroupEventCursor, GroupEventKind, GroupEventSubscriber,
    GroupMemberId, GroupName, ProcessGroupState,
};
use asupersync::types::{TaskId, Time};

/// A deterministic join-schedule entry: (node name, task index).
type JoinScheduleEntry = (&'static str, u32);

fn member(node: &str, task: u32) -> GroupMemberId {
    GroupMemberId::new(NodeId::new(node), TaskId::new_for_test(task, 0))
}

/// Build a group and apply a join schedule at `t = join_index` nanoseconds, so
/// each member gets a distinct, deterministic join sequence and timestamp.
fn group_from_schedule(name: &str, schedule: &[JoinScheduleEntry]) -> ProcessGroupState {
    let mut state = ProcessGroupState::new(GroupName::new(name).expect("valid group name"));
    for (index, (node, task)) in schedule.iter().enumerate() {
        state
            .join(member(node, *task), Time::from_nanos(index as u64))
            .expect("first join of a member succeeds");
    }
    state
}

/// Drain every currently-pending event for a subscriber, committing each batch,
/// and return the flattened event sequence numbers observed in order.
fn drain_sequences(state: &ProcessGroupState, subscriber: &mut GroupEventSubscriber) -> Vec<u64> {
    let mut observed = Vec::new();
    loop {
        let batch = subscriber.pending_batch(state);
        if batch.events().is_empty() {
            break;
        }
        observed.extend(batch.events().iter().map(|event| event.sequence()));
        assert!(
            subscriber.commit(&batch),
            "committing a fresh pending batch must advance the subscriber"
        );
    }
    observed
}

#[test]
fn snapshot_member_order_is_deterministic_registration_order() {
    // The join order deliberately disagrees with GroupMemberId sort order: we
    // join node-c, then node-a, then node-b. A naive BTreeMap iteration would
    // surface them as a/b/c; registration order must surface c/a/b.
    let schedule: [JoinScheduleEntry; 3] = [("node-c", 30), ("node-a", 10), ("node-b", 20)];

    let first = group_from_schedule("workers", &schedule);
    let second = group_from_schedule("workers", &schedule);

    let order_first: Vec<GroupMemberId> = first.snapshot().member_ids().cloned().collect();
    let order_second: Vec<GroupMemberId> = second.snapshot().member_ids().cloned().collect();

    assert_eq!(
        order_first,
        vec![
            member("node-c", 30),
            member("node-a", 10),
            member("node-b", 20)
        ],
        "snapshot must preserve registration (join-sequence) order, not key order"
    );
    assert_eq!(
        order_first, order_second,
        "the same join schedule must yield an identical member ordering across runs"
    );
}

#[test]
fn broadcast_recipients_follow_snapshot_registration_order() {
    let schedule: [JoinScheduleEntry; 4] = [
        ("node-d", 40),
        ("node-b", 20),
        ("node-c", 30),
        ("node-a", 10),
    ];
    let state = group_from_schedule("fanout", &schedule);

    let snapshot_order: Vec<GroupMemberId> = state.snapshot().member_ids().cloned().collect();

    for policy in [
        BroadcastBackpressurePolicy::Wait,
        BroadcastBackpressurePolicy::Skip,
        BroadcastBackpressurePolicy::Error,
    ] {
        let plan = state.broadcast_plan(policy);
        assert_eq!(plan.policy(), policy, "plan records the requested policy");
        assert_eq!(
            plan.recipients(),
            snapshot_order.as_slice(),
            "broadcast recipients must match snapshot registration order for {policy:?}"
        );
    }
}

#[test]
fn monitor_subscriber_observes_each_event_exactly_once() {
    let mut state = ProcessGroupState::new(GroupName::new("monitored").expect("valid name"));
    let a = member("node-a", 1);
    let b = member("node-b", 2);

    // Four transitions: join a, join b, leave a, down b. Each emits exactly one
    // monotonically-sequenced event.
    state.join(a.clone(), Time::from_nanos(1)).expect("join a");
    state.join(b.clone(), Time::from_nanos(2)).expect("join b");
    state.leave(&a, Time::from_nanos(3)).expect("leave a");
    state
        .mark_down(
            &b,
            asupersync::monitor::DownReason::Normal,
            Time::from_nanos(4),
        )
        .expect("down b");

    let mut subscriber = GroupEventSubscriber::new();
    let first_drain = drain_sequences(&state, &mut subscriber);
    assert_eq!(
        first_drain,
        vec![0, 1, 2, 3],
        "the subscriber must observe all four transitions exactly once, in order"
    );

    // Kinds line up with the transition order.
    let kinds: Vec<&GroupEventKind> = state.event_log().iter().map(|e| e.kind()).collect();
    assert!(matches!(kinds[0], GroupEventKind::Joined));
    assert!(matches!(kinds[1], GroupEventKind::Joined));
    assert!(matches!(kinds[2], GroupEventKind::Left));
    assert!(matches!(kinds[3], GroupEventKind::Down(_)));

    // Re-draining without new events yields nothing — committed events are never
    // re-delivered (exactly-once).
    let second_drain = drain_sequences(&state, &mut subscriber);
    assert!(
        second_drain.is_empty(),
        "no committed event may be re-delivered, got {second_drain:?}"
    );

    // A new transition is delivered exactly once, with no replay of the prior
    // four events.
    let c = member("node-c", 3);
    state.join(c, Time::from_nanos(5)).expect("join c");
    let third_drain = drain_sequences(&state, &mut subscriber);
    assert_eq!(
        third_drain,
        vec![4],
        "only the new event is delivered after prior events were committed"
    );
}

#[test]
fn stale_batch_commit_cannot_rewind_the_stream() {
    let mut state = ProcessGroupState::new(GroupName::new("rewind-guard").expect("valid name"));
    state
        .join(member("node-a", 1), Time::from_nanos(1))
        .expect("join a");
    state
        .join(member("node-b", 2), Time::from_nanos(2))
        .expect("join b");

    // Capture a batch from the start, advance the subscriber fully, then attempt
    // to commit the now-stale start batch.
    let mut subscriber = GroupEventSubscriber::new();
    let stale_batch = state.event_batch(GroupEventCursor::new());
    assert_eq!(drain_sequences(&state, &mut subscriber), vec![0, 1]);

    assert!(
        !subscriber.commit(&stale_batch),
        "committing a stale batch must be a no-op and report no advance"
    );
    // The stream stays at the end: still nothing pending.
    assert!(
        drain_sequences(&state, &mut subscriber).is_empty(),
        "a stale-batch commit must not rewind the subscriber"
    );
}
