#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::lab::LabRuntime;
use asupersync::record::ObligationKind;
use asupersync::types::Budget;
use asupersync_macros::lab_test;

#[lab_test]
fn runtime_form_gets_seed_zero(lab: &mut LabRuntime) {
    assert_eq!(lab.config().seed, 0);
}

#[lab_test(seeds = 2..5)]
fn seed_matrix_runs_every_seed(lab: &mut LabRuntime) {
    assert!((2..5).contains(&lab.config().seed));
}

#[lab_test(seeds = 7..8, chaos)]
fn chaos_uses_light_profile(lab: &mut LabRuntime) {
    assert_eq!(lab.config().seed, 7);
    assert!(lab.has_chaos());
}

#[lab_test]
async fn async_cx_form_gets_current_cx(cx: &Cx) {
    assert_eq!(
        cx.region_id(),
        Cx::current().expect("current Cx").region_id()
    );
}

#[should_panic(expected = "seed 3")]
#[lab_test(seeds = 2..5)]
fn seed_matrix_failure_reports_seed(lab: &mut LabRuntime) {
    assert_ne!(lab.config().seed, 3, "intentional seed failure");
}

#[should_panic(expected = "obligation leak")]
#[lab_test]
fn obligation_leak_fails_after_body(lab: &mut LabRuntime) {
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task_id, _handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    lab.state
        .create_obligation(ObligationKind::SendPermit, task_id, root, None)
        .expect("create obligation");
    lab.scheduler
        .lock()
        .schedule(task_id, Budget::INFINITE.priority);
}
