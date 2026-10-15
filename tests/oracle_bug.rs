//! Regression test for supervision oracle restart-limit escalation handling.

use asupersync::actor::ActorId;
use asupersync::lab::oracle::actor::*;
use asupersync::supervision::{EscalationPolicy, RestartPolicy};
use asupersync::types::{TaskId, Time};

fn actor(n: u32) -> ActorId {
    ActorId::from_task(TaskId::new_for_test(n, 0))
}
fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

#[test]
fn one_for_all_escalation_after_restart_limit_passes_without_sibling_restarts() {
    let mut oracle = SupervisionOracle::new();
    oracle.register_supervisor(
        actor(0),
        RestartPolicy::OneForAll,
        1,
        EscalationPolicy::Escalate,
    );
    oracle.register_child(actor(0), actor(1));
    oracle.register_child(actor(0), actor(2));

    // First failure: restarts
    oracle.on_child_failed(actor(0), actor(1), t(10), "error1".into());
    oracle.on_restart(actor(1), 1, t(20));
    oracle.on_restart(actor(2), 1, t(20));

    // Second failure: exceeds limit, escalates (NO restarts)
    oracle.on_child_failed(actor(0), actor(1), t(30), "error2".into());
    oracle.on_escalation(actor(0), actor(99), t(50), "limit".into());

    assert!(
        oracle.check(t(100)).is_ok(),
        "supervisor-originated escalation should close the second failure window"
    );
}
