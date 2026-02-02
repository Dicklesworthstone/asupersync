//! Oracle integration tests for actors.
//!
//! These tests verify that the actor-specific oracles correctly detect
//! invariant violations in the lab runtime. These tests focus on the
//! LabRuntime integration rather than the individual oracle unit tests
//! (which are already in src/lab/oracle/actor.rs).

use crate::actor_e2e::util::init_actor_test;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;

#[test]
fn oracle_suite_includes_actor_oracles() {
    init_actor_test("oracle_suite_includes_actor_oracles");

    let runtime = LabRuntime::new(LabConfig::new(42));

    // Verify the oracles field is accessible and properly initialized
    let actor_count = runtime.oracles.actor_leak.actor_count();
    assert_with_log!(actor_count == 0, "actor count starts at 0", 0, actor_count);

    let mailbox_count = runtime.oracles.mailbox.mailbox_count();
    assert_with_log!(
        mailbox_count == 0,
        "mailbox count starts at 0",
        0,
        mailbox_count
    );
}

#[test]
fn lab_runtime_oracles_clean_by_default() {
    init_actor_test("lab_runtime_oracles_clean_by_default");

    let runtime = LabRuntime::new(LabConfig::new(42));

    // Fresh runtime should have no violations
    let violations = runtime.oracles.check_all(runtime.now());
    let violation_count = violations.len();

    assert_with_log!(
        violation_count == 0,
        "fresh runtime should have no violations",
        0,
        violation_count
    );
}

#[test]
fn lab_runtime_creates_root_region() {
    init_actor_test("lab_runtime_creates_root_region");

    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // The region should be created successfully (non-panicking is the test)
    let _ = format!("{region:?}"); // Just verify it's usable
}

#[test]
fn lab_runtime_oracles_reset() {
    init_actor_test("lab_runtime_oracles_reset");

    let mut runtime = LabRuntime::new(LabConfig::new(42));

    // Reset the oracles
    runtime.oracles.reset();

    // Should still be clean
    let violations = runtime.oracles.check_all(runtime.now());
    let violation_count = violations.len();

    assert_with_log!(
        violation_count == 0,
        "reset oracles should have no violations",
        0,
        violation_count
    );
}
