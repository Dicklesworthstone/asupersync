//! Value-layer proofs for `spork::process_group` (bead asupersync-dist-otp-completeness-8y37kz.1).
//!
//! The process-group module ships a deterministic synchronous value layer
//! (`ProcessGroupState`) that the future async `join`/`broadcast`/`monitor_group`
//! surfaces build on. Several of its acceptance criteria are properties of that
//! value layer rather than of the not-yet-wired runtime:
//!
//! * AC3 — `members()` ordering and broadcast delivery order are stable across
//!   same-seed runs (registration-ordered, deterministic, policy-independent).
//! * AC4 — 1000-member churn (joins interleaved with leaves and downs and
//!   broadcasts) is leak-free: membership stays exact, the event log carries one
//!   contiguous sequence per transition, and every broadcast plan equals the
//!   live membership.
//! * AC5 — the monitor event stream delivers every membership event exactly once
//!   (metamorphic: one-shot delivery and one-event-at-a-time delivery produce the
//!   identical sequence; re-delivery and stale commits never move the stream).
//!
//! This is an integration test on the public prelude surface, so it links the
//! library in non-test mode and exercises only committed, exported API. It does
//! not touch `src/spork.rs`; the runtime-wiring ACs (lease-backed join, real
//! message delivery/backpressure execution, oracle matrices) remain open.

use std::collections::BTreeSet;

use asupersync::remote::NodeId;
use asupersync::spork::prelude::{
    BroadcastBackpressurePolicy, DownReason, GroupEventCursor, GroupEventKind,
    GroupEventSubscriber, GroupMemberId, GroupName, ProcessGroupState,
};
use asupersync::types::{TaskId, Time};

/// Deterministic member id from a node label and task index.
fn member(node: &str, task_index: u32) -> GroupMemberId {
    GroupMemberId::new(NodeId::new(node), TaskId::new_for_test(task_index, 0))
}

fn group(name: &str) -> ProcessGroupState {
    ProcessGroupState::new(GroupName::new(name).expect("valid group name"))
}

/// Builds a fixed three-member group, joining in reverse-id order so the join
/// sequence deliberately disagrees with id order.
fn build_workers() -> ProcessGroupState {
    let mut state = group("workers");
    state
        .join(member("node-z", 9), Time::from_nanos(100))
        .expect("join z");
    state
        .join(member("node-m", 5), Time::from_nanos(101))
        .expect("join m");
    state
        .join(member("node-a", 1), Time::from_nanos(102))
        .expect("join a");
    state
}

// -- AC3: determinism ---------------------------------------------------------

#[test]
fn snapshot_and_broadcast_order_are_registration_ordered_and_reproducible() {
    let s1 = build_workers();
    let s2 = build_workers();

    let ids1: Vec<GroupMemberId> = s1.snapshot().member_ids().cloned().collect();
    let ids2: Vec<GroupMemberId> = s2.snapshot().member_ids().cloned().collect();

    // Reproducibility: identical operations yield identical membership order.
    assert_eq!(ids1, ids2, "same-seed runs must produce identical order");

    // The order follows registration (join sequence), NOT member-id order:
    // node-z joined first even though it sorts last by id.
    assert_eq!(
        ids1,
        vec![
            member("node-z", 9),
            member("node-m", 5),
            member("node-a", 1)
        ],
        "snapshot must be join-sequence ordered, not id ordered",
    );

    // Snapshot member records expose the same registration order with monotone
    // join sequences.
    let snap = s1.snapshot();
    let seqs: Vec<u64> = snap.members().iter().map(|m| m.join_sequence()).collect();
    assert_eq!(
        seqs,
        vec![0, 1, 2],
        "join sequences are monotone in join order"
    );

    // Broadcast recipient order matches the snapshot order for every policy,
    // and the policy is carried verbatim.
    for policy in [
        BroadcastBackpressurePolicy::Wait,
        BroadcastBackpressurePolicy::Skip,
        BroadcastBackpressurePolicy::Error,
    ] {
        let plan = s1.broadcast_plan(policy);
        assert_eq!(
            plan.recipients(),
            ids1.as_slice(),
            "broadcast recipients must match deterministic snapshot order",
        );
        assert_eq!(
            plan.policy(),
            policy,
            "broadcast plan must carry the policy"
        );
        assert_eq!(plan.group(), s1.group());
    }
}

// -- AC4: 1000-member churn, leak-free ---------------------------------------

#[test]
fn thousand_member_churn_is_leak_free_and_membership_exact() {
    const N: u32 = 1000;

    let mut state = group("churn");
    // Ground-truth active set. All members share one node and an increasing task
    // index, so id order == join order == snapshot order, which lets us compare
    // the snapshot directly to this set.
    let mut active: BTreeSet<GroupMemberId> = BTreeSet::new();
    let mut removed: BTreeSet<GroupMemberId> = BTreeSet::new();
    let mut clock: u64 = 0;
    let mut total_events: u64 = 0;

    let active_vec = |active: &BTreeSet<GroupMemberId>| -> Vec<GroupMemberId> {
        active.iter().cloned().collect()
    };

    for i in 0..N {
        let m = member("node", i);
        state
            .join(m.clone(), Time::from_nanos(clock))
            .expect("join");
        clock += 1;
        total_events += 1;
        assert!(active.insert(m.clone()), "join target must be fresh");

        // Every third step: an explicit leave of the lowest active member.
        if i % 3 == 2 && active.len() >= 2 {
            let victim = active.iter().next().cloned().expect("victim");
            state
                .leave(&victim, Time::from_nanos(clock))
                .expect("leave");
            clock += 1;
            total_events += 1;
            assert!(active.remove(&victim));
            assert!(removed.insert(victim));
        }

        // Every fifth step: a monitor-driven down of the highest active member.
        if i % 5 == 4 && active.len() >= 2 {
            let victim = active.iter().next_back().cloned().expect("victim");
            state
                .mark_down(&victim, DownReason::Normal, Time::from_nanos(clock))
                .expect("down");
            clock += 1;
            total_events += 1;
            assert!(active.remove(&victim));
            assert!(removed.insert(victim));
        }

        // Periodic invariant checkpoint: live membership and every broadcast
        // plan exactly track the ground-truth active set.
        if i % 100 == 99 {
            assert_eq!(state.len(), active.len(), "len must track active set");
            let expected = active_vec(&active);
            let snap_ids: Vec<GroupMemberId> = state.snapshot().member_ids().cloned().collect();
            assert_eq!(snap_ids, expected, "snapshot must equal active set");
            let plan = state.broadcast_plan(BroadcastBackpressurePolicy::Wait);
            assert_eq!(
                plan.recipients(),
                expected.as_slice(),
                "broadcast plan must equal live membership during churn",
            );
        }
    }

    // Final exact membership.
    assert_eq!(state.len(), active.len());
    for m in &active {
        assert!(state.contains_member(m), "active member must be present");
    }
    for m in &removed {
        assert!(
            !state.contains_member(m),
            "removed member must not linger (no leak)",
        );
    }
    // Disjointness sanity: nothing is both active and removed.
    assert!(active.is_disjoint(&removed));

    // The event log carries exactly one event per transition, with a contiguous,
    // gap-free, duplicate-free sequence — the value-layer "leak-free" witness.
    let log = state.event_log();
    assert_eq!(
        log.len() as u64,
        total_events,
        "one event per successful transition",
    );
    for (idx, event) in log.iter().enumerate() {
        assert_eq!(
            event.sequence(),
            idx as u64,
            "event sequence must be contiguous"
        );
    }
    assert_eq!(
        state.next_event_sequence(),
        total_events,
        "next sequence equals the number of emitted events",
    );

    // Draining the whole log through a cursor yields each event exactly once.
    let mut cursor = GroupEventCursor::new();
    let drained = state.events_since(&mut cursor).len();
    assert_eq!(
        drained as u64, total_events,
        "cursor drains every event once"
    );
    assert!(
        state.events_since(&mut cursor).is_empty(),
        "a caught-up cursor delivers nothing further",
    );
}

// -- AC5: monitor stream delivers exactly once (metamorphic) ------------------

#[derive(Clone)]
enum Op {
    Join(GroupMemberId),
    Leave(GroupMemberId),
    Down(GroupMemberId, DownReason),
}

#[test]
fn monitor_stream_delivers_every_event_exactly_once() {
    let node_one = member("node", 1);
    let node_two = member("node", 2);
    let node_three = member("node", 3);
    let node_four = member("node", 4);

    let ops = vec![
        Op::Join(node_one.clone()),
        Op::Join(node_two.clone()),
        Op::Join(node_three.clone()),
        Op::Leave(node_two.clone()),
        Op::Down(node_one.clone(), DownReason::Normal),
        Op::Join(node_four.clone()),
        Op::Down(node_three.clone(), DownReason::Error("crash".into())),
    ];
    let operation_count = ops.len() as u64;

    let mut state = group("monitor");

    // Incremental subscriber: drains after every single op (one event each).
    let mut sub_inc = GroupEventSubscriber::new();
    let mut incremental: Vec<u64> = Vec::new();

    for (clock, op) in (0_u64..).zip(ops.iter()) {
        match op {
            Op::Join(member_id) => {
                state
                    .join(member_id.clone(), Time::from_nanos(clock))
                    .expect("join");
            }
            Op::Leave(member_id) => {
                state
                    .leave(member_id, Time::from_nanos(clock))
                    .expect("leave");
            }
            Op::Down(member_id, reason) => {
                state
                    .mark_down(member_id, reason.clone(), Time::from_nanos(clock))
                    .expect("down");
            }
        }

        let batch = sub_inc.pending_batch(&state);
        assert_eq!(batch.len(), 1, "each op emits exactly one pending event");
        incremental.push(batch.events()[0].sequence());
        assert!(
            sub_inc.commit(&batch),
            "fresh batch must advance the cursor"
        );
    }

    // All-at-once subscriber: drains the whole log in a single batch.
    let mut sub_all = GroupEventSubscriber::new();
    let batch_all = sub_all.pending_batch(&state);
    let all_at_once: Vec<u64> = batch_all.events().iter().map(|e| e.sequence()).collect();
    assert!(sub_all.commit(&batch_all));

    // Metamorphic relation: chunking granularity does not change the delivered
    // sequence, and every event appears exactly once with no gaps.
    let contiguous: Vec<u64> = (0..operation_count).collect();
    assert_eq!(
        all_at_once, contiguous,
        "all-at-once must deliver 0..n once"
    );
    assert_eq!(
        incremental, all_at_once,
        "incremental and all-at-once deliveries must be identical",
    );

    // Exactly-once: a caught-up subscriber delivers nothing further.
    assert!(sub_all.pending_batch(&state).is_empty());
    assert!(sub_inc.pending_batch(&state).is_empty());

    // Re-committing an already-applied (now stale) batch is a no-op: the stream
    // can never be moved backward by retry/cleanup.
    assert!(
        !sub_all.commit(&batch_all),
        "stale commit must not move the cursor backward",
    );
    assert!(sub_all.pending_batch(&state).is_empty());

    // Content witness: the event log records the exact membership story so the
    // "exactly once" guarantee is over the right events, not just the right count.
    let log = state.event_log();
    assert_eq!(log.len(), ops.len());
    assert!(matches!(log[0].kind(), GroupEventKind::Joined) && log[0].member() == &a);
    assert!(matches!(log[1].kind(), GroupEventKind::Joined) && log[1].member() == &b);
    assert!(matches!(log[2].kind(), GroupEventKind::Joined) && log[2].member() == &c);
    assert!(matches!(log[3].kind(), GroupEventKind::Left) && log[3].member() == &b);
    assert!(
        matches!(log[4].kind(), GroupEventKind::Down(DownReason::Normal)) && log[4].member() == &a
    );
    assert!(matches!(log[5].kind(), GroupEventKind::Joined) && log[5].member() == &d);
    assert!(
        matches!(log[6].kind(), GroupEventKind::Down(DownReason::Error(_)))
            && log[6].member() == &c
    );
}

// -- one-shot cursor relation -------------------------------------------------

#[test]
fn events_since_one_shot_equals_event_log_and_is_idempotent() {
    let state = build_workers();

    let mut cursor = GroupEventCursor::new();
    let one_shot: Vec<_> = state.events_since(&mut cursor).to_vec();
    assert_eq!(
        one_shot.as_slice(),
        state.event_log(),
        "a fresh cursor drains exactly the full event log",
    );
    assert_eq!(cursor.next_sequence(), state.next_event_sequence());

    // Re-reading from the advanced cursor yields nothing (no double delivery).
    assert!(state.events_since(&mut cursor).is_empty());
}
