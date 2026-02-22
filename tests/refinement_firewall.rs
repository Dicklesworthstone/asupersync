//! Integration tests for trace refinement firewall checks.

use asupersync::record::ObligationKind;
use asupersync::trace::{
    TraceData, TraceEvent, TraceEventKind, check_refinement_firewall, first_counterexample_prefix,
    verify_refinement_firewall,
};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};

fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn oid(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

#[test]
fn firewall_reports_deterministic_first_violation() {
    let events = vec![
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::new(
            2,
            Time::ZERO,
            TraceEventKind::CancelAck,
            TraceData::Cancel {
                task: tid(1),
                region: rid(1),
                reason: CancelReason::shutdown(),
            },
        ),
        TraceEvent::obligation_commit(
            3,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
            1,
        ),
    ];

    let run_a = check_refinement_firewall(&events);
    let run_b = check_refinement_firewall(&events);

    assert_eq!(run_a, run_b);
    assert!(!run_a.is_ok());
    let violation = run_a.first_violation.expect("expected violation");
    assert_eq!(violation.rule_id, "RFW-CANCEL-006");
    assert_eq!(violation.event_index, 1);
}

#[test]
fn firewall_counterexample_prefix_stops_at_first_failure() {
    let events = vec![
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        TraceEvent::obligation_reserve(
            3,
            Time::ZERO,
            oid(1),
            tid(999),
            rid(1),
            ObligationKind::Ack,
        ),
    ];

    let prefix = first_counterexample_prefix(&events).expect("expected prefix");
    assert_eq!(prefix.len(), 2);
    assert_eq!(prefix[1].seq, 2);
}

#[test]
fn firewall_verify_ok_for_valid_trace() {
    let events = vec![
        TraceEvent::region_created(1, Time::ZERO, rid(1), None),
        TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        TraceEvent::obligation_reserve(
            3,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::Lease,
        ),
        TraceEvent::obligation_commit(
            4,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::Lease,
            5,
        ),
        TraceEvent::complete(5, Time::ZERO, tid(1), rid(1)),
        TraceEvent::new(
            6,
            Time::ZERO,
            TraceEventKind::RegionCloseBegin,
            TraceData::Region {
                region: rid(1),
                parent: None,
            },
        ),
        TraceEvent::new(
            7,
            Time::ZERO,
            TraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: rid(1),
                parent: None,
            },
        ),
    ];

    verify_refinement_firewall(&events).expect("valid trace should pass");
}
