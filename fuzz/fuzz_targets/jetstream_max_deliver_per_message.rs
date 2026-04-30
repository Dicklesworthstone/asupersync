#![no_main]

//! Structure-aware fuzz target for local JetStream MaxDeliver enforcement.

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{
    FuzzMaxDeliverState, FuzzMaxDeliverStep, FuzzMaxDeliverTerminal, fuzz_apply_max_deliver_step,
};
use libfuzzer_sys::fuzz_target;

const MAX_STEPS: usize = 128;

#[derive(Arbitrary, Debug)]
struct Scenario {
    max_deliver: i16,
    steps: Vec<StepSpec>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StepSpec {
    Redeliver,
    Ack,
    ResetMessage,
}

fuzz_target!(|scenario: Scenario| {
    let max_deliver = i64::from(scenario.max_deliver);
    let mut actual = FuzzMaxDeliverState {
        max_deliver,
        delivered: 0,
        accepted_deliveries: 0,
        rejected_deliveries: 0,
        dlq_messages: 0,
        terminal: FuzzMaxDeliverTerminal::Pending,
    };
    let mut model = actual.clone();

    for spec in scenario.steps.into_iter().take(MAX_STEPS) {
        let step = map_step(spec);
        fuzz_apply_max_deliver_step(&mut actual, step);
        apply_model_step(&mut model, step);

        assert_eq!(
            actual, model,
            "max-deliver reducer diverged on step {step:?}"
        );

        let effective_limit = actual.max_deliver.max(-1);
        match actual.terminal {
            FuzzMaxDeliverTerminal::Pending | FuzzMaxDeliverTerminal::Acked => {
                if effective_limit >= 0 {
                    assert!(
                        i64::from(actual.delivered) <= effective_limit,
                        "active/acked message must not exceed finite max_deliver: {actual:?}"
                    );
                }
            }
            FuzzMaxDeliverTerminal::DeadLettered => {
                assert!(
                    actual.dlq_messages > 0,
                    "dead-lettered state must record a dlq transition: {actual:?}"
                );
                assert!(
                    actual.rejected_deliveries > 0,
                    "dead-lettered state must record a rejected delivery: {actual:?}"
                );
                if effective_limit >= 0 {
                    assert!(
                        i64::from(actual.delivered) > effective_limit,
                        "dead-lettered message must exceed the finite max_deliver cap: {actual:?}"
                    );
                }
            }
        }
    }
});

fn map_step(step: StepSpec) -> FuzzMaxDeliverStep {
    match step {
        StepSpec::Redeliver => FuzzMaxDeliverStep::Redeliver,
        StepSpec::Ack => FuzzMaxDeliverStep::Ack,
        StepSpec::ResetMessage => FuzzMaxDeliverStep::ResetMessage,
    }
}

fn apply_model_step(state: &mut FuzzMaxDeliverState, step: FuzzMaxDeliverStep) {
    let max_deliver = state.max_deliver.max(-1);

    match step {
        FuzzMaxDeliverStep::Redeliver => match state.terminal {
            FuzzMaxDeliverTerminal::Pending => {
                let delivered = state.delivered.saturating_add(1);
                state.delivered = delivered;

                if max_deliver >= 0 && i64::from(delivered) > max_deliver {
                    state.rejected_deliveries = state.rejected_deliveries.saturating_add(1);
                    state.dlq_messages = state.dlq_messages.saturating_add(1);
                    state.terminal = FuzzMaxDeliverTerminal::DeadLettered;
                } else {
                    state.accepted_deliveries = state.accepted_deliveries.saturating_add(1);
                }
            }
            FuzzMaxDeliverTerminal::Acked | FuzzMaxDeliverTerminal::DeadLettered => {
                state.rejected_deliveries = state.rejected_deliveries.saturating_add(1);
            }
        },
        FuzzMaxDeliverStep::Ack => {
            if matches!(state.terminal, FuzzMaxDeliverTerminal::Pending) && state.delivered > 0 {
                state.terminal = FuzzMaxDeliverTerminal::Acked;
            }
        }
        FuzzMaxDeliverStep::ResetMessage => {
            state.delivered = 0;
            state.terminal = FuzzMaxDeliverTerminal::Pending;
        }
    }
}
