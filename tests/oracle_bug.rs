#![allow(missing_docs)]
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
fn test_oracle_bug() {
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

    // Because it did not restart, restart_count is 0!
    // And it will trigger OneForAllNotFollowed instead!
    let res = oracle.check(t(100));
    println!("{res:?}");
}
