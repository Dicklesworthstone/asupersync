//! Tests for ActorId type.
//!
//! Note: The comprehensive ActorId unit tests are in src/actor.rs.
//! These E2E tests focus on verifying ActorState which has a public API.

use crate::actor_e2e::util::init_actor_test;
use asupersync::actor::ActorState;

#[test]
fn actor_state_values_are_distinct() {
    init_actor_test("actor_state_values_are_distinct");

    let states = [
        ActorState::Created,
        ActorState::Running,
        ActorState::Stopping,
        ActorState::Stopped,
    ];

    // All states should be distinct from each other
    for (i, a) in states.iter().enumerate() {
        for (j, b) in states.iter().enumerate() {
            if i == j {
                let eq = a == b;
                assert_with_log!(eq, "same state should equal itself", true, eq);
            } else {
                let neq = a != b;
                assert_with_log!(
                    neq,
                    &format!("{a:?} should not equal {b:?}"),
                    true,
                    neq
                );
            }
        }
    }
}

#[test]
fn actor_state_debug_output() {
    init_actor_test("actor_state_debug_output");

    let debug_created = format!("{:?}", ActorState::Created);
    let debug_running = format!("{:?}", ActorState::Running);
    let debug_stopping = format!("{:?}", ActorState::Stopping);
    let debug_stopped = format!("{:?}", ActorState::Stopped);

    let created_ok = debug_created.contains("Created");
    let running_ok = debug_running.contains("Running");
    let stopping_ok = debug_stopping.contains("Stopping");
    let stopped_ok = debug_stopped.contains("Stopped");

    assert_with_log!(created_ok, "Created debug", true, created_ok);
    assert_with_log!(running_ok, "Running debug", true, running_ok);
    assert_with_log!(stopping_ok, "Stopping debug", true, stopping_ok);
    assert_with_log!(stopped_ok, "Stopped debug", true, stopped_ok);
}

#[test]
fn actor_state_is_copy() {
    init_actor_test("actor_state_is_copy");

    let state = ActorState::Running;
    let copied = state; // Copy
    let eq = state == copied;

    assert_with_log!(eq, "copied state should equal original", true, eq);
}
