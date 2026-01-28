mod common;
use common::*;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;

fn run_program(runtime: &mut LabRuntime) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async { 1u8 })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();
}

#[test]
fn determinism_trace_bytes_match() {
    init_test_logging();
    test_phase!("determinism_trace_bytes_match");

    let seed = DEFAULT_TEST_SEED;
    let config = LabConfig::new(seed).with_default_replay_recording();

    let mut runtime1 = LabRuntime::new(config.clone());
    run_program(&mut runtime1);
    let trace1 = runtime1
        .finish_replay_trace()
        .expect("replay trace 1");
    let bytes1 = trace1.to_bytes().expect("serialize trace 1");

    let mut runtime2 = LabRuntime::new(config);
    run_program(&mut runtime2);
    let trace2 = runtime2
        .finish_replay_trace()
        .expect("replay trace 2");
    let bytes2 = trace2.to_bytes().expect("serialize trace 2");

    assert_eq!(bytes1, bytes2, "replay trace bytes diverged");

    test_complete!("determinism_trace_bytes_match");
}
