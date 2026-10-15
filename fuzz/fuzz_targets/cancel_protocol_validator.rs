#![no_main]

//! Structured fuzzing for `CancelProtocolValidator`.
//!
//! The input is interpreted as a compact trace script over bounded IDs 1-4:
//! `r<id><op>` for region register/transition, `t<task><region>+` for task
//! registration, `t<id><op>` for task transitions, `o<obligation><region>+`
//! for obligation registration, and `o<id><op>` for obligation transitions.
//! The fuzzer accepts any byte stream, normalizes IDs into 1-4, and compares
//! validator results against shadow state machines for registered entities while
//! asserting that unregistered transitions are rejected and counted.

use asupersync::cancel::protocol_state_machines::{
    CancelProtocolValidator, CancelStateMachine, ObligationContext, ObligationEvent,
    ObligationStateMachine, RegionContext, RegionEvent, RegionStateMachine, TaskContext, TaskEvent,
    TaskStateMachine, TransitionResult, ValidationLevel,
};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

const MAX_OPS: usize = 64;
const MAX_IDS: u8 = 4;

#[derive(Debug)]
struct ShadowRegion {
    machine: RegionStateMachine,
    context: RegionContext,
}

#[derive(Debug)]
struct ShadowTask {
    machine: TaskStateMachine,
    context: TaskContext,
}

#[derive(Debug)]
struct ShadowObligation {
    machine: ObligationStateMachine,
    context: ObligationContext,
}

#[derive(Debug)]
enum ScriptOp {
    RegisterRegion {
        region_id: RegionId,
    },
    RegionTransition {
        region_id: RegionId,
        event: RegionEvent,
    },
    RegisterTask {
        task_id: TaskId,
        region_id: RegionId,
    },
    TaskTransition {
        task_id: TaskId,
        event: TaskEvent,
    },
    RegisterObligation {
        obligation_id: ObligationId,
        region_id: RegionId,
    },
    ObligationTransition {
        obligation_id: ObligationId,
        event: ObligationEvent,
    },
}

fuzz_target!(|data: &[u8]| {
    let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
    let mut regions = HashMap::<RegionId, ShadowRegion>::new();
    let mut tasks = HashMap::<TaskId, ShadowTask>::new();
    let mut obligations = HashMap::<ObligationId, ShadowObligation>::new();

    for op in parse_script(data) {
        match op {
            ScriptOp::RegisterRegion { region_id } => {
                validator.register_region(region_id);
                regions.insert(region_id, shadow_region(region_id));
            }
            ScriptOp::RegionTransition { region_id, event } => {
                let before = validator.violation_count();
                let expected_delta = if let Some(shadow) = regions.get_mut(&region_id) {
                    let expected = shadow.machine.transition(event.clone(), &shadow.context);
                    let actual = run_region_transition(
                        &mut validator,
                        region_id,
                        event.clone(),
                        &shadow.context,
                    );
                    assert_eq!(actual, expected, "region result mismatch for {region_id:?}");
                    assert_eq!(
                        validator.region_state(region_id),
                        Some(shadow.machine.current_state()),
                        "validator region state diverged for {region_id:?}"
                    );
                    let mut expected_delta = expected_violation_delta(&expected);
                    if shadow.machine.is_terminal() {
                        assert_region_terminal_idempotence(
                            &mut validator,
                            region_id,
                            event,
                            shadow,
                        );
                        expected_delta += 1;
                    }
                    expected_delta
                } else {
                    let context = region_context(region_id);
                    let actual =
                        run_region_transition(&mut validator, region_id, event.clone(), &context);
                    assert_unregistered_invalid(&actual, "region");
                    1
                };
                assert_eq!(
                    validator.violation_count(),
                    before + expected_delta,
                    "region violation_count delta mismatch"
                );
            }
            ScriptOp::RegisterTask { task_id, region_id } => {
                validator.register_task(task_id, region_id);
                tasks.insert(task_id, shadow_task(task_id, region_id));
            }
            ScriptOp::TaskTransition { task_id, event } => {
                let before = validator.violation_count();
                let expected_delta = if let Some(shadow) = tasks.get_mut(&task_id) {
                    let expected = shadow.machine.transition(event.clone(), &shadow.context);
                    let actual = run_task_transition(
                        &mut validator,
                        task_id,
                        event.clone(),
                        &shadow.context,
                    );
                    assert_eq!(actual, expected, "task result mismatch for {task_id:?}");
                    assert_eq!(
                        validator.task_state(task_id),
                        Some(shadow.machine.current_state()),
                        "validator task state diverged for {task_id:?}"
                    );
                    let mut expected_delta = expected_violation_delta(&expected);
                    if shadow.machine.is_terminal() {
                        assert_task_terminal_idempotence(&mut validator, task_id, event, shadow);
                        expected_delta += 1;
                    }
                    expected_delta
                } else {
                    let context = task_context(task_id, default_region_for_task());
                    let actual =
                        run_task_transition(&mut validator, task_id, event.clone(), &context);
                    assert_unregistered_invalid(&actual, "task");
                    1
                };
                assert_eq!(
                    validator.violation_count(),
                    before + expected_delta,
                    "task violation_count delta mismatch"
                );
            }
            ScriptOp::RegisterObligation {
                obligation_id,
                region_id,
            } => {
                validator.register_obligation(obligation_id);
                obligations.insert(obligation_id, shadow_obligation(obligation_id, region_id));
            }
            ScriptOp::ObligationTransition {
                obligation_id,
                event,
            } => {
                let before = validator.violation_count();
                let expected_delta = if let Some(shadow) = obligations.get_mut(&obligation_id) {
                    let expected = shadow.machine.transition(event.clone(), &shadow.context);
                    let actual = run_obligation_transition(
                        &mut validator,
                        obligation_id,
                        event.clone(),
                        &shadow.context,
                    );
                    assert_eq!(
                        actual, expected,
                        "obligation result mismatch for {obligation_id:?}"
                    );
                    let mut expected_delta = expected_violation_delta(&expected);
                    if shadow.machine.is_terminal() {
                        assert_obligation_terminal_idempotence(
                            &mut validator,
                            obligation_id,
                            event,
                            shadow,
                        );
                        expected_delta += 1;
                    }
                    expected_delta
                } else {
                    let context =
                        obligation_context(obligation_id, default_region_for_obligation());
                    let actual = run_obligation_transition(
                        &mut validator,
                        obligation_id,
                        event.clone(),
                        &context,
                    );
                    assert_unregistered_invalid(&actual, "obligation");
                    1
                };
                assert_eq!(
                    validator.violation_count(),
                    before + expected_delta,
                    "obligation violation_count delta mismatch"
                );
            }
        }
    }

    let (region_count, task_count, obligation_count, _, _, _, violations) = validator.stats();
    assert_eq!(
        region_count,
        regions.len(),
        "validator region stats drifted"
    );
    assert_eq!(task_count, tasks.len(), "validator task stats drifted");
    assert_eq!(
        obligation_count,
        obligations.len(),
        "validator obligation stats drifted"
    );
    assert_eq!(
        violations,
        validator.violation_count(),
        "validator stats violation count drifted"
    );
});

fn parse_script(data: &[u8]) -> Vec<ScriptOp> {
    let mut ops = Vec::new();
    let mut index = 0;
    while index < data.len() && ops.len() < MAX_OPS {
        let byte = data[index];
        if byte.is_ascii_whitespace() || matches!(byte, b',' | b';' | b'|') {
            index += 1;
            continue;
        }

        match byte {
            b'r' if index + 2 < data.len() => {
                let region_id = region_id_from_byte(data[index + 1]);
                let op = data[index + 2];
                if op == b'+' {
                    ops.push(ScriptOp::RegisterRegion { region_id });
                } else {
                    ops.push(ScriptOp::RegionTransition {
                        region_id,
                        event: region_event(op, region_id),
                    });
                }
                index += 3;
            }
            b't' if index + 3 < data.len() && data[index + 3] == b'+' => {
                ops.push(ScriptOp::RegisterTask {
                    task_id: task_id_from_byte(data[index + 1]),
                    region_id: region_id_from_byte(data[index + 2]),
                });
                index += 4;
            }
            b't' if index + 2 < data.len() => {
                ops.push(ScriptOp::TaskTransition {
                    task_id: task_id_from_byte(data[index + 1]),
                    event: task_event(data[index + 2], task_id_from_byte(data[index + 1])),
                });
                index += 3;
            }
            b'o' if index + 3 < data.len() && data[index + 3] == b'+' => {
                ops.push(ScriptOp::RegisterObligation {
                    obligation_id: obligation_id_from_byte(data[index + 1]),
                    region_id: region_id_from_byte(data[index + 2]),
                });
                index += 4;
            }
            b'o' if index + 2 < data.len() => {
                ops.push(ScriptOp::ObligationTransition {
                    obligation_id: obligation_id_from_byte(data[index + 1]),
                    event: obligation_event(
                        data[index + 2],
                        obligation_id_from_byte(data[index + 1]),
                    ),
                });
                index += 3;
            }
            _ => {
                index += 1;
            }
        }
    }
    ops
}

fn region_event(byte: u8, region_id: RegionId) -> RegionEvent {
    match byte {
        b'A' => RegionEvent::Activate,
        b'T' => RegionEvent::TaskSpawned,
        b'c' => RegionEvent::TaskCompleted,
        b'D' => RegionEvent::TaskDrained,
        b'K' => RegionEvent::Cancel {
            reason: format!("cancel-region-{region_id:?}"),
        },
        b'F' => RegionEvent::FinalizerRegistered,
        b'S' => RegionEvent::FinalizerStarted,
        b'E' => RegionEvent::FinalizerCompleted,
        b'X' => RegionEvent::RequestClose,
        _ => match byte % 9 {
            0 => RegionEvent::Activate,
            1 => RegionEvent::TaskSpawned,
            2 => RegionEvent::TaskCompleted,
            3 => RegionEvent::TaskDrained,
            4 => RegionEvent::Cancel {
                reason: format!("cancel-region-{region_id:?}"),
            },
            5 => RegionEvent::FinalizerRegistered,
            6 => RegionEvent::FinalizerStarted,
            7 => RegionEvent::FinalizerCompleted,
            _ => RegionEvent::RequestClose,
        },
    }
}

fn task_event(byte: u8, task_id: TaskId) -> TaskEvent {
    match byte {
        b'S' => TaskEvent::Start,
        b'K' => TaskEvent::RequestCancel,
        b'C' => TaskEvent::Complete,
        b'D' => TaskEvent::DrainComplete,
        b'P' => TaskEvent::Panic {
            message: format!("panic-task-{task_id:?}"),
        },
        _ => match byte % 5 {
            0 => TaskEvent::Start,
            1 => TaskEvent::RequestCancel,
            2 => TaskEvent::Complete,
            3 => TaskEvent::DrainComplete,
            _ => TaskEvent::Panic {
                message: format!("panic-task-{task_id:?}"),
            },
        },
    }
}

fn obligation_event(byte: u8, obligation_id: ObligationId) -> ObligationEvent {
    match byte {
        b'R' => ObligationEvent::Reserve {
            token: obligation_token(obligation_id),
        },
        b'C' => ObligationEvent::Commit,
        b'A' => ObligationEvent::Abort {
            reason: format!("abort-obligation-{obligation_id:?}"),
        },
        _ => match byte % 3 {
            0 => ObligationEvent::Reserve {
                token: obligation_token(obligation_id),
            },
            1 => ObligationEvent::Commit,
            _ => ObligationEvent::Abort {
                reason: format!("abort-obligation-{obligation_id:?}"),
            },
        },
    }
}

fn run_region_transition(
    validator: &mut CancelProtocolValidator,
    region_id: RegionId,
    event: RegionEvent,
    context: &RegionContext,
) -> TransitionResult {
    let before = validator.violation_count();
    let result = validator.validate_region_transition(region_id, event, context);
    assert!(
        validator.violation_count() >= before,
        "region violation_count regressed"
    );
    result
}

fn run_task_transition(
    validator: &mut CancelProtocolValidator,
    task_id: TaskId,
    event: TaskEvent,
    context: &TaskContext,
) -> TransitionResult {
    let before = validator.violation_count();
    let result = validator.validate_task_transition(task_id, event, context);
    assert!(
        validator.violation_count() >= before,
        "task violation_count regressed"
    );
    result
}

fn run_obligation_transition(
    validator: &mut CancelProtocolValidator,
    obligation_id: ObligationId,
    event: ObligationEvent,
    context: &ObligationContext,
) -> TransitionResult {
    let before = validator.violation_count();
    let result = validator.validate_obligation_transition(obligation_id, event, context);
    assert!(
        validator.violation_count() >= before,
        "obligation violation_count regressed"
    );
    result
}

fn assert_region_terminal_idempotence(
    validator: &mut CancelProtocolValidator,
    region_id: RegionId,
    event: RegionEvent,
    shadow: &mut ShadowRegion,
) {
    let before = validator.violation_count();
    let actual = validator.validate_region_transition(region_id, event.clone(), &shadow.context);
    let expected = shadow.machine.transition(event, &shadow.context);
    assert_eq!(actual, expected, "region terminal replay diverged");
    assert!(
        matches!(actual, TransitionResult::Invalid { .. }),
        "region terminal replay must be invalid"
    );
    assert_eq!(
        validator.violation_count(),
        before + 1,
        "region terminal replay must increment violation_count once"
    );
    assert_eq!(
        validator.region_state(region_id),
        Some(shadow.machine.current_state()),
        "validator region state changed on terminal replay"
    );
}

fn assert_task_terminal_idempotence(
    validator: &mut CancelProtocolValidator,
    task_id: TaskId,
    event: TaskEvent,
    shadow: &mut ShadowTask,
) {
    let before = validator.violation_count();
    let actual = validator.validate_task_transition(task_id, event.clone(), &shadow.context);
    let expected = shadow.machine.transition(event, &shadow.context);
    assert_eq!(actual, expected, "task terminal replay diverged");
    assert!(
        matches!(actual, TransitionResult::Invalid { .. }),
        "task terminal replay must be invalid"
    );
    assert_eq!(
        validator.violation_count(),
        before + 1,
        "task terminal replay must increment violation_count once"
    );
    assert_eq!(
        validator.task_state(task_id),
        Some(shadow.machine.current_state()),
        "validator task state changed on terminal replay"
    );
}

fn assert_obligation_terminal_idempotence(
    validator: &mut CancelProtocolValidator,
    obligation_id: ObligationId,
    event: ObligationEvent,
    shadow: &mut ShadowObligation,
) {
    let before = validator.violation_count();
    let actual =
        validator.validate_obligation_transition(obligation_id, event.clone(), &shadow.context);
    let expected = shadow.machine.transition(event, &shadow.context);
    assert_eq!(actual, expected, "obligation terminal replay diverged");
    assert!(
        matches!(actual, TransitionResult::Invalid { .. }),
        "obligation terminal replay must be invalid"
    );
    assert_eq!(
        validator.violation_count(),
        before + 1,
        "obligation terminal replay must increment violation_count once"
    );
}

fn assert_unregistered_invalid(result: &TransitionResult, entity: &str) {
    match result {
        TransitionResult::Invalid {
            reason,
            current_state,
            ..
        } => {
            assert!(
                reason.contains("not registered with validator"),
                "{entity} unregistered reason mismatch: {reason}"
            );
            assert_eq!(current_state, "Unknown", "{entity} current_state mismatch");
        }
        _ => {
            panic!("{entity} unregistered transition must be invalid: {result:?}");
        }
    }
}

fn expected_violation_delta(result: &TransitionResult) -> u64 {
    match result {
        TransitionResult::Valid => 0,
        TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. } => 1,
    }
}

fn shadow_region(region_id: RegionId) -> ShadowRegion {
    ShadowRegion {
        machine: RegionStateMachine::new(region_id, ValidationLevel::Full),
        context: region_context(region_id),
    }
}

fn shadow_task(task_id: TaskId, region_id: RegionId) -> ShadowTask {
    ShadowTask {
        machine: TaskStateMachine::new(task_id, region_id, ValidationLevel::Full),
        context: task_context(task_id, region_id),
    }
}

fn shadow_obligation(obligation_id: ObligationId, region_id: RegionId) -> ShadowObligation {
    ShadowObligation {
        machine: ObligationStateMachine::new(obligation_id, ValidationLevel::Full),
        context: obligation_context(obligation_id, region_id),
    }
}

fn region_context(region_id: RegionId) -> RegionContext {
    RegionContext {
        region_id,
        parent_region: None,
        created_at: Time::ZERO,
        validation_level: ValidationLevel::Full,
    }
}

fn task_context(task_id: TaskId, region_id: RegionId) -> TaskContext {
    TaskContext {
        task_id,
        region_id,
        spawned_at: Time::ZERO,
        validation_level: ValidationLevel::Full,
    }
}

fn obligation_context(obligation_id: ObligationId, region_id: RegionId) -> ObligationContext {
    ObligationContext {
        obligation_id,
        region_id,
        created_at: Time::ZERO,
        validation_level: ValidationLevel::Full,
    }
}

fn region_id_from_byte(byte: u8) -> RegionId {
    RegionId::new_for_test(normalize_id(byte), 0)
}

fn task_id_from_byte(byte: u8) -> TaskId {
    TaskId::new_for_test(normalize_id(byte), 0)
}

fn obligation_id_from_byte(byte: u8) -> ObligationId {
    ObligationId::new_for_test(normalize_id(byte), 0)
}

fn default_region_for_task() -> RegionId {
    RegionId::new_for_test(1, 0)
}

fn default_region_for_obligation() -> RegionId {
    RegionId::new_for_test(1, 0)
}

fn obligation_token(_obligation_id: ObligationId) -> u64 {
    7
}

fn normalize_id(byte: u8) -> u32 {
    u32::from(byte % MAX_IDS) + 1
}
