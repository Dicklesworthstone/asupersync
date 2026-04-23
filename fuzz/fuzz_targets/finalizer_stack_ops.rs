//! Fuzz target for `record::finalizer::FinalizerStack` operation invariants.
//!
//! This target exercises stack mutation order and policy bookkeeping:
//! 1. `len()` and `is_empty()` stay consistent with the modeled stack depth.
//! 2. `pop()` returns items in strict LIFO order across sync/async mixes.
//! 3. Sync finalizers preserve the captured tag when executed after pop.
//! 4. Escalation policy accessors remain stable across arbitrary operations.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::record::finalizer::{Finalizer, FinalizerEscalation, FinalizerStack};
use libfuzzer_sys::fuzz_target;
use parking_lot::Mutex;
use std::sync::Arc;

const MAX_OPS: usize = 128;

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum ModelFinalizer {
    Sync(u8),
    Async,
}

#[derive(Arbitrary, Debug, Clone)]
enum StackOp {
    PushSync(u8),
    PushAsync,
    PopOne,
    DrainAll,
}

#[derive(Arbitrary, Debug)]
struct FinalizerStackInput {
    escalation: u8,
    ops: Vec<StackOp>,
}

fn decode_escalation(raw: u8) -> FinalizerEscalation {
    match raw % 3 {
        0 => FinalizerEscalation::Soft,
        1 => FinalizerEscalation::BoundedLog,
        _ => FinalizerEscalation::BoundedPanic,
    }
}

fn assert_stack_shape(stack: &FinalizerStack, model: &[ModelFinalizer], escalation: FinalizerEscalation) {
    assert_eq!(stack.len(), model.len(), "stack length diverged from model");
    assert_eq!(stack.is_empty(), model.is_empty(), "is_empty diverged from model");
    assert_eq!(stack.escalation(), escalation, "escalation policy drifted");
    assert_eq!(
        stack.escalation().allows_continuation(),
        matches!(escalation, FinalizerEscalation::BoundedLog),
        "allows_continuation mismatch"
    );
    assert_eq!(
        stack.escalation().is_soft(),
        matches!(escalation, FinalizerEscalation::Soft),
        "is_soft mismatch"
    );
}

fuzz_target!(|input: FinalizerStackInput| {
    let escalation = decode_escalation(input.escalation);
    let mut stack = FinalizerStack::with_escalation(escalation);
    let mut model = Vec::new();
    let sync_log = Arc::new(Mutex::new(Vec::<u8>::new()));

    for op in input.ops.into_iter().take(MAX_OPS) {
        match op {
            StackOp::PushSync(tag) => {
                let log = Arc::clone(&sync_log);
                stack.push(Finalizer::Sync(Box::new(move || {
                    log.lock().push(tag);
                })));
                model.push(ModelFinalizer::Sync(tag));
            }
            StackOp::PushAsync => {
                stack.push(Finalizer::Async(Box::pin(async {})));
                model.push(ModelFinalizer::Async);
            }
            StackOp::PopOne => {
                let expected = model.pop();
                let actual = stack.pop();
                match (expected, actual) {
                    (None, None) => {}
                    (Some(ModelFinalizer::Sync(expected_tag)), Some(Finalizer::Sync(f))) => {
                        f();
                        let observed = sync_log.lock().pop();
                        assert_eq!(observed, Some(expected_tag), "sync finalizer tag mismatch");
                    }
                    (Some(ModelFinalizer::Async), Some(Finalizer::Async(_))) => {}
                    (expected_kind, actual_kind) => {
                        panic!(
                            "pop mismatch: expected={expected_kind:?} actual_sync={} actual_async={}",
                            matches!(actual_kind, Some(Finalizer::Sync(_))),
                            matches!(actual_kind, Some(Finalizer::Async(_)))
                        );
                    }
                }
            }
            StackOp::DrainAll => {
                while let Some(expected) = model.pop() {
                    let actual = stack.pop().expect("stack pop must match model during drain");
                    match (expected, actual) {
                        (ModelFinalizer::Sync(expected_tag), Finalizer::Sync(f)) => {
                            f();
                            let observed = sync_log.lock().pop();
                            assert_eq!(observed, Some(expected_tag), "drain sync tag mismatch");
                        }
                        (ModelFinalizer::Async, Finalizer::Async(_)) => {}
                        (expected_kind, actual_kind) => {
                            panic!(
                                "drain mismatch: expected={expected_kind:?} actual_sync={} actual_async={}",
                                matches!(actual_kind, Finalizer::Sync(_)),
                                matches!(actual_kind, Finalizer::Async(_))
                            );
                        }
                    }
                }
                assert!(stack.pop().is_none(), "stack not empty after draining model");
            }
        }

        assert_stack_shape(&stack, &model, escalation);
    }

    while let Some(expected) = model.pop() {
        let actual = stack.pop().expect("final drain must match model");
        match (expected, actual) {
            (ModelFinalizer::Sync(expected_tag), Finalizer::Sync(f)) => {
                f();
                let observed = sync_log.lock().pop();
                assert_eq!(observed, Some(expected_tag), "final sync tag mismatch");
            }
            (ModelFinalizer::Async, Finalizer::Async(_)) => {}
            (expected_kind, actual_kind) => {
                panic!(
                    "final drain mismatch: expected={expected_kind:?} actual_sync={} actual_async={}",
                    matches!(actual_kind, Finalizer::Sync(_)),
                    matches!(actual_kind, Finalizer::Async(_))
                );
            }
        }
    }

    assert_stack_shape(&stack, &model, escalation);
});
