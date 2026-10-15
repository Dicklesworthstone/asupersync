#![no_main]

//! Structure-aware fuzz target for the JetStream pull-subscriber loop reducer.

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{
    FuzzPullSubscriberState, FuzzPullSubscriberStep, FuzzPullSubscriberTerminal,
    fuzz_apply_pull_subscriber_step,
};
use libfuzzer_sys::fuzz_target;

const MAX_STEPS: usize = 128;

#[derive(Arbitrary, Debug)]
struct Scenario {
    batch: u8,
    steps: Vec<StepSpec>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StepSpec {
    ParsedMessage,
    IgnoredMessage,
    ProcessReady,
    ProcessClosed,
    ProcessTimedOut,
    ProcessError,
}

fuzz_target!(|scenario: Scenario| {
    let batch = usize::from((scenario.batch % 8) + 1);
    let mut actual = FuzzPullSubscriberState {
        batch,
        received: 0,
        ignored: 0,
        terminal: FuzzPullSubscriberTerminal::Active,
    };
    let mut model = actual.clone();

    for spec in scenario.steps.into_iter().take(MAX_STEPS) {
        let step = map_step(spec);
        fuzz_apply_pull_subscriber_step(&mut actual, step);
        apply_model_step(&mut model, step);

        assert_eq!(actual, model, "pull subscriber diverged on step {step:?}");
        assert!(actual.received <= actual.batch, "{actual:?}");
        if matches!(actual.terminal, FuzzPullSubscriberTerminal::Completed) {
            assert_eq!(actual.received, actual.batch, "{actual:?}");
        }
    }
});

fn map_step(step: StepSpec) -> FuzzPullSubscriberStep {
    match step {
        StepSpec::ParsedMessage => FuzzPullSubscriberStep::ParsedMessage,
        StepSpec::IgnoredMessage => FuzzPullSubscriberStep::IgnoredMessage,
        StepSpec::ProcessReady => FuzzPullSubscriberStep::ProcessReady,
        StepSpec::ProcessClosed => FuzzPullSubscriberStep::ProcessClosed,
        StepSpec::ProcessTimedOut => FuzzPullSubscriberStep::ProcessTimedOut,
        StepSpec::ProcessError => FuzzPullSubscriberStep::ProcessError,
    }
}

fn apply_model_step(state: &mut FuzzPullSubscriberState, step: FuzzPullSubscriberStep) {
    if !matches!(state.terminal, FuzzPullSubscriberTerminal::Active) {
        return;
    }

    match step {
        FuzzPullSubscriberStep::ParsedMessage => {
            state.received = state.received.saturating_add(1).min(state.batch);
            if state.received >= state.batch {
                state.terminal = FuzzPullSubscriberTerminal::Completed;
            }
        }
        FuzzPullSubscriberStep::IgnoredMessage => {
            state.ignored = state.ignored.saturating_add(1);
        }
        FuzzPullSubscriberStep::ProcessReady => {}
        FuzzPullSubscriberStep::ProcessClosed => {
            state.terminal = FuzzPullSubscriberTerminal::Closed;
        }
        FuzzPullSubscriberStep::ProcessTimedOut => {
            state.terminal = FuzzPullSubscriberTerminal::TimedOut;
        }
        FuzzPullSubscriberStep::ProcessError => {
            state.terminal = FuzzPullSubscriberTerminal::Error;
        }
    }
}
