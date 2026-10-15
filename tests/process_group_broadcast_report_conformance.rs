//! Broadcast-accounting conformance for `spork::process_group` (bead
//! asupersync-dist-otp-completeness-8y37kz.1).
//!
//! AC2 of the process-group feature is the *no-silent-drop* boundary: a
//! broadcast may deliver, skip, or backpressure a recipient, but it must account
//! for **every** planned recipient deterministically, keeping skip and
//! backpressure counts distinct so the async delivery surface never collapses a
//! policy effect into a generic partial-failure bucket.
//!
//! The deterministic accounting types that enforce this — `immediate_delivery_
//! report`, `GroupBroadcastReport::{from_plan, all_delivered, all_skipped,
//! all_backpressured}`, and `GroupBroadcastSummary` — had zero integration
//! coverage. The existing value-layer proofs only exercise the recipient *plan*
//! and the monitor subscriber, not the post-delivery report/summary. This file
//! pins the report layer through the public prelude surface, oracle-free: every
//! expectation is recomputed from the plan and the (synthetic) per-recipient
//! outcome, with no decode/runtime needed.
//!
//! The runtime-wiring ACs (lease-backed join, real async backpressure execution)
//! remain open; this proves only the synchronous accounting these types promise.
//!
//! Repro: `cargo test --features test-internals --test process_group_broadcast_report_conformance`

use asupersync::remote::NodeId;
use asupersync::spork::prelude::{
    BroadcastBackpressurePolicy, GroupBroadcastPlan, GroupBroadcastRecipientStatus,
    GroupBroadcastReport, GroupBroadcastSummary, GroupMemberId, GroupName, GroupSnapshot,
    ProcessGroupError, ProcessGroupState,
};
use asupersync::types::{TaskId, Time};

// ---------------------------------------------------------------------------
// Construction helpers (reuse the existing value-layer proof idioms)
// ---------------------------------------------------------------------------

fn member(node: &str, task_index: u32) -> GroupMemberId {
    GroupMemberId::new(NodeId::new(node), TaskId::new_for_test(task_index, 0))
}

/// Builds a deterministic snapshot, joining in the given order so the recipient
/// order under test is registration order, not id order.
fn snapshot(members: &[(&str, u32)]) -> GroupSnapshot {
    let mut state = ProcessGroupState::new(GroupName::new("workers").expect("valid group name"));
    for (i, (node, task)) in members.iter().enumerate() {
        state
            .join(member(node, *task), Time::from_nanos(100 + i as u64))
            .expect("join");
    }
    state.snapshot()
}

fn plan(members: &[(&str, u32)], policy: BroadcastBackpressurePolicy) -> GroupBroadcastPlan {
    GroupBroadcastPlan::from_snapshot(&snapshot(members), policy)
}

const FLEET: &[(&str, u32)] = &[
    ("node-z", 9),
    ("node-m", 5),
    ("node-a", 1),
    ("node-q", 7),
    ("node-c", 3),
];

// ---------------------------------------------------------------------------
// No-silent-drop: every planned recipient is accounted for, exactly once.
// ---------------------------------------------------------------------------

#[test]
fn immediate_report_accounts_for_every_recipient_exactly_once() {
    for policy in [
        BroadcastBackpressurePolicy::Wait,
        BroadcastBackpressurePolicy::Skip,
        BroadcastBackpressurePolicy::Error,
    ] {
        let p = plan(FLEET, policy);
        // Accept every other recipient; the rest are blocked.
        let mut idx = 0usize;
        let report = p.immediate_delivery_report(|_member| {
            let accept = idx % 2 == 0;
            idx += 1;
            accept
        });

        // One row per planned recipient — no drops, no phantom rows.
        assert_eq!(report.len(), p.len(), "row count must equal plan size");
        let summary = report.summary();
        assert_eq!(
            summary.total(),
            p.len(),
            "summary total must equal plan size under {policy:?}"
        );
        // The three buckets partition the plan exactly.
        assert_eq!(
            summary.delivered() + summary.skipped() + summary.backpressured(),
            p.len(),
            "buckets must partition the recipients under {policy:?}"
        );
        // Report counts and summary fields are the same accounting.
        assert_eq!(report.delivered_count(), summary.delivered());
        assert_eq!(report.skipped_count(), summary.skipped());
        assert_eq!(report.backpressured_count(), summary.backpressured());
    }
}

// ---------------------------------------------------------------------------
// Policy classification: a blocked recipient is Skipped under Skip, and
// Backpressured under Wait/Error — never collapsed together.
// ---------------------------------------------------------------------------

#[test]
fn blocked_recipient_classification_follows_policy() {
    // Reject exactly the same two members under each policy.
    let reject = |m: &GroupMemberId| {
        m.node() == &NodeId::new("node-m") || m.node() == &NodeId::new("node-c")
    };
    let accept = |m: &GroupMemberId| !reject(m);

    let skip = plan(FLEET, BroadcastBackpressurePolicy::Skip).immediate_delivery_report(&accept);
    let wait = plan(FLEET, BroadcastBackpressurePolicy::Wait).immediate_delivery_report(&accept);
    let error = plan(FLEET, BroadcastBackpressurePolicy::Error).immediate_delivery_report(&accept);

    // Delivered count is policy-independent (the accepted members).
    assert_eq!(skip.delivered_count(), 3);
    assert_eq!(wait.delivered_count(), 3);
    assert_eq!(error.delivered_count(), 3);

    // Skip routes blocked members to the skip bucket only.
    assert_eq!(skip.skipped_count(), 2);
    assert_eq!(skip.backpressured_count(), 0);
    assert!(skip.summary().has_skipped_recipients());
    assert!(!skip.summary().has_backpressured_recipients());

    // Wait and Error route blocked members to the backpressure bucket only.
    for report in [&wait, &error] {
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.backpressured_count(), 2);
        assert!(report.summary().has_backpressured_recipients());
        assert!(!report.summary().has_skipped_recipients());
    }
}

// ---------------------------------------------------------------------------
// Order preservation: report rows follow the plan's (registration) order.
// ---------------------------------------------------------------------------

#[test]
fn report_preserves_plan_recipient_order() {
    let p = plan(FLEET, BroadcastBackpressurePolicy::Wait);
    let report = p.immediate_delivery_report(|_| true);

    let plan_order: Vec<&GroupMemberId> = p.recipients().iter().collect();
    let report_order: Vec<&GroupMemberId> =
        report.recipients().iter().map(|r| r.member()).collect();
    assert_eq!(report_order, plan_order, "report must keep plan order");

    // Registration order, not id order: node-z (joined first) precedes node-a.
    let z = p
        .recipients()
        .iter()
        .position(|m| m.node() == &NodeId::new("node-z"));
    let a = p
        .recipients()
        .iter()
        .position(|m| m.node() == &NodeId::new("node-a"));
    assert!(z < a, "registration order must win over id order");
}

// ---------------------------------------------------------------------------
// Differential: from_plan reconstructs the same report regardless of the input
// order, and agrees with immediate_delivery_report.
// ---------------------------------------------------------------------------

#[test]
fn from_plan_is_input_order_independent_and_matches_immediate() {
    let policy = BroadcastBackpressurePolicy::Skip;
    let p = plan(FLEET, policy);

    let reject = |m: &GroupMemberId| m.node() == &NodeId::new("node-q");
    let immediate = p.immediate_delivery_report(|m| !reject(m));

    // Build the same outcomes, then feed them in REVERSED order: from_plan must
    // re-emit in plan order, producing a report equal to the immediate one.
    let mut outcomes: Vec<(GroupMemberId, GroupBroadcastRecipientStatus)> = p
        .recipients()
        .iter()
        .cloned()
        .map(|m| {
            let status = if reject(&m) {
                GroupBroadcastRecipientStatus::Skipped
            } else {
                GroupBroadcastRecipientStatus::Delivered
            };
            (m, status)
        })
        .collect();
    outcomes.reverse();

    let rebuilt = GroupBroadcastReport::from_plan(&p, outcomes).expect("valid outcomes");
    assert_eq!(
        rebuilt, immediate,
        "from_plan must agree with immediate report"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed: from_plan rejects unknown, duplicate, and missing recipients.
// ---------------------------------------------------------------------------

#[test]
fn from_plan_rejects_unknown_recipient() {
    let p = plan(FLEET, BroadcastBackpressurePolicy::Wait);
    let ghost = member("ghost", 99);
    let mut outcomes: Vec<(GroupMemberId, GroupBroadcastRecipientStatus)> = p
        .recipients()
        .iter()
        .cloned()
        .map(|m| (m, GroupBroadcastRecipientStatus::Delivered))
        .collect();
    outcomes.push((ghost.clone(), GroupBroadcastRecipientStatus::Delivered));

    match GroupBroadcastReport::from_plan(&p, outcomes) {
        Err(ProcessGroupError::BroadcastRecipientUnknown(m)) => assert_eq!(m, ghost),
        other => panic!("expected BroadcastRecipientUnknown, got {other:?}"),
    }
}

#[test]
fn from_plan_rejects_duplicate_recipient() {
    let p = plan(FLEET, BroadcastBackpressurePolicy::Wait);
    let dup = p.recipients()[0].clone();
    let mut outcomes: Vec<(GroupMemberId, GroupBroadcastRecipientStatus)> = p
        .recipients()
        .iter()
        .cloned()
        .map(|m| (m, GroupBroadcastRecipientStatus::Delivered))
        .collect();
    outcomes.push((dup.clone(), GroupBroadcastRecipientStatus::Skipped));

    match GroupBroadcastReport::from_plan(&p, outcomes) {
        Err(ProcessGroupError::BroadcastRecipientDuplicate(m)) => assert_eq!(m, dup),
        other => panic!("expected BroadcastRecipientDuplicate, got {other:?}"),
    }
}

#[test]
fn from_plan_rejects_missing_recipient() {
    let p = plan(FLEET, BroadcastBackpressurePolicy::Wait);
    let omitted = p.recipients().last().expect("non-empty plan").clone();
    let outcomes: Vec<(GroupMemberId, GroupBroadcastRecipientStatus)> = p
        .recipients()
        .iter()
        .filter(|m| **m != omitted)
        .cloned()
        .map(|m| (m, GroupBroadcastRecipientStatus::Delivered))
        .collect();

    match GroupBroadcastReport::from_plan(&p, outcomes) {
        Err(ProcessGroupError::BroadcastRecipientMissing(m)) => assert_eq!(m, omitted),
        other => panic!("expected BroadcastRecipientMissing, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Summary algebra and uniform constructors.
// ---------------------------------------------------------------------------

#[test]
fn uniform_constructors_yield_single_bucket_summaries() {
    let p = plan(FLEET, BroadcastBackpressurePolicy::Skip);
    let n = p.len();

    let delivered = GroupBroadcastReport::all_delivered(&p);
    assert!(delivered.is_all_delivered());
    assert_eq!(delivered.summary(), GroupBroadcastSummary::new(n, 0, 0));

    let skipped = GroupBroadcastReport::all_skipped(&p);
    assert!(!skipped.is_all_delivered());
    assert_eq!(skipped.summary(), GroupBroadcastSummary::new(0, n, 0));
    assert!(skipped.summary().has_skipped_recipients());

    let backpressured = GroupBroadcastReport::all_backpressured(&p);
    assert!(!backpressured.is_all_delivered());
    assert_eq!(backpressured.summary(), GroupBroadcastSummary::new(0, 0, n));
    assert!(backpressured.summary().has_backpressured_recipients());
}

#[test]
fn summary_total_and_all_delivered_are_consistent() {
    // is_all_delivered() <=> no skip and no backpressure, and total is the sum.
    let cases = [
        (5, 0, 0, true),
        (3, 2, 0, false),
        (3, 0, 2, false),
        (0, 0, 0, true),
    ];
    for (d, s, b, all) in cases {
        let summary = GroupBroadcastSummary::new(d, s, b);
        assert_eq!(summary.total(), d + s + b);
        assert_eq!(summary.is_all_delivered(), all, "summary {summary:?}");
        assert_eq!(summary.has_skipped_recipients(), s > 0);
        assert_eq!(summary.has_backpressured_recipients(), b > 0);
    }
}

// ---------------------------------------------------------------------------
// Empty group: the no-drop accounting is vacuously satisfied.
// ---------------------------------------------------------------------------

#[test]
fn empty_plan_reports_nothing_and_is_vacuously_all_delivered() {
    let p = plan(&[], BroadcastBackpressurePolicy::Wait);
    assert!(p.is_empty());

    let report = p.immediate_delivery_report(|_| false);
    assert!(report.is_empty());
    assert_eq!(report.len(), 0);
    let summary = report.summary();
    assert_eq!(summary.total(), 0);
    assert!(summary.is_all_delivered(), "empty broadcast drops nothing");

    // from_plan with no outcomes is the same empty report.
    let rebuilt = GroupBroadcastReport::from_plan(&p, Vec::new()).expect("empty outcomes");
    assert_eq!(rebuilt, report);
}
