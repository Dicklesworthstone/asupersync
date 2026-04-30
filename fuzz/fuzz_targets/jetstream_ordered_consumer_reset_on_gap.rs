#![no_main]

//! Structure-aware fuzz target for the JetStream ordered-consumer reset-on-gap
//! reducer.

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{
    FuzzOrderedConsumerPhase, FuzzOrderedConsumerState, FuzzOrderedConsumerStep,
    fuzz_apply_ordered_consumer_step,
};
use libfuzzer_sys::fuzz_target;

const MAX_STEPS: usize = 128;

#[derive(Arbitrary, Debug)]
struct Scenario {
    steps: Vec<StepSpec>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StepSpec {
    Observe { sequence: u16, delivered: u8 },
    CompleteReset,
}

fuzz_target!(|scenario: Scenario| {
    let mut actual = FuzzOrderedConsumerState {
        phase: FuzzOrderedConsumerPhase::Tracking,
        last_sequence: None,
        accepted_messages: 0,
        reset_count: 0,
        pending_gap_from: None,
    };
    let mut model = actual.clone();

    for spec in scenario.steps.into_iter().take(MAX_STEPS) {
        let step = map_step(spec);
        fuzz_apply_ordered_consumer_step(&mut actual, step);
        apply_model_step(&mut model, step);

        assert_eq!(
            actual, model,
            "ordered consumer reducer diverged on step {step:?}"
        );
        if matches!(actual.phase, FuzzOrderedConsumerPhase::Tracking) {
            assert!(
                actual.pending_gap_from.is_none(),
                "tracking state must not retain pending gap metadata: {actual:?}"
            );
        }
        if let Some(last_sequence) = actual.last_sequence {
            assert!(
                actual.accepted_messages > 0,
                "tracked sequence must imply at least one accepted message: last_sequence={last_sequence} state={actual:?}"
            );
        }
    }
});

fn map_step(step: StepSpec) -> FuzzOrderedConsumerStep {
    match step {
        StepSpec::Observe {
            sequence,
            delivered,
        } => FuzzOrderedConsumerStep::Observe {
            sequence: u64::from(sequence),
            delivered: u32::from(delivered),
        },
        StepSpec::CompleteReset => FuzzOrderedConsumerStep::CompleteReset,
    }
}

fn apply_model_step(state: &mut FuzzOrderedConsumerState, step: FuzzOrderedConsumerStep) {
    match step {
        FuzzOrderedConsumerStep::Observe {
            sequence,
            delivered,
        } => match state.phase {
            FuzzOrderedConsumerPhase::Tracking => {
                let contiguous = state
                    .last_sequence
                    .is_none_or(|last| sequence == last.saturating_add(1));
                if delivered == 1 && contiguous {
                    state.last_sequence = Some(sequence);
                    state.accepted_messages = state.accepted_messages.saturating_add(1);
                } else {
                    state.phase = FuzzOrderedConsumerPhase::ResetPending;
                    state.reset_count = state.reset_count.saturating_add(1);
                    state.pending_gap_from = state.last_sequence.map(|last| last.saturating_add(1));
                }
            }
            FuzzOrderedConsumerPhase::ResetPending => {}
        },
        FuzzOrderedConsumerStep::CompleteReset => {
            if matches!(state.phase, FuzzOrderedConsumerPhase::ResetPending) {
                state.phase = FuzzOrderedConsumerPhase::Tracking;
                state.last_sequence = None;
                state.pending_gap_from = None;
            }
        }
    }
}
