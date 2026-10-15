#![no_main]

//! Structure-aware fuzz target for Redis SUBSCRIBE/UNSUBSCRIBE bookkeeping.
//!
//! Bead: br-asupersync-7rjadd

use arbitrary::Arbitrary;
use asupersync::messaging::redis::{
    FuzzPubSubLane, FuzzPubSubOp, FuzzPubSubState, fuzz_apply_pubsub_state_step,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

const MAX_OPS: usize = 96;
const MAX_NAMES_PER_OP: usize = 4;

#[derive(Arbitrary, Debug)]
struct Scenario {
    ops: Vec<Operation>,
}

#[derive(Arbitrary, Debug, Clone)]
struct Operation {
    lane: Lane,
    op: OpKind,
    names: Vec<NameSpec>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Lane {
    Channel,
    Pattern,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum OpKind {
    Subscribe,
    Unsubscribe,
}

#[derive(Arbitrary, Debug, Clone)]
enum NameSpec {
    Empty,
    Duplicate(u8),
    Unique(u8),
    Long(u8),
}

fuzz_target!(|scenario: Scenario| {
    let mut actual = FuzzPubSubState {
        channels: Vec::new(),
        patterns: Vec::new(),
    };
    let mut model_channels = Vec::new();
    let mut model_patterns = Vec::new();

    for op in scenario.ops.into_iter().take(MAX_OPS) {
        let lane = match op.lane {
            Lane::Channel => FuzzPubSubLane::Channel,
            Lane::Pattern => FuzzPubSubLane::Pattern,
        };
        let kind = match op.op {
            OpKind::Subscribe => FuzzPubSubOp::Subscribe,
            OpKind::Unsubscribe => FuzzPubSubOp::Unsubscribe,
        };

        let mut names: Vec<String> = op
            .names
            .into_iter()
            .take(MAX_NAMES_PER_OP)
            .enumerate()
            .map(|(index, spec)| spec.materialize(index))
            .collect();
        if matches!(kind, FuzzPubSubOp::Subscribe) && names.is_empty() {
            names.push("fallback".to_string());
        }

        let result = fuzz_apply_pubsub_state_step(&mut actual, lane, kind, &names);
        let expected_result =
            apply_model_step(&mut model_channels, &mut model_patterns, lane, kind, &names);

        assert_eq!(
            result.is_ok(),
            expected_result.is_ok(),
            "state-step result mismatch for {kind:?} on {lane:?} with names {names:?}"
        );
        if let Err(err) = result {
            panic!("unexpected helper error for {kind:?} on {lane:?}: {err}");
        }

        assert_eq!(
            actual.channels, model_channels,
            "channel state diverged after {kind:?} on {lane:?} with names {names:?}"
        );
        assert_eq!(
            actual.patterns, model_patterns,
            "pattern state diverged after {kind:?} on {lane:?} with names {names:?}"
        );
        assert_no_duplicates(&actual.channels, "channels");
        assert_no_duplicates(&actual.patterns, "patterns");
    }
});

fn apply_model_step(
    channels: &mut Vec<String>,
    patterns: &mut Vec<String>,
    lane: FuzzPubSubLane,
    op: FuzzPubSubOp,
    values: &[String],
) -> Result<(), ()> {
    let list = match lane {
        FuzzPubSubLane::Channel => channels,
        FuzzPubSubLane::Pattern => patterns,
    };

    match op {
        FuzzPubSubOp::Subscribe => {
            if values.is_empty() {
                return Err(());
            }
            for value in values {
                if !list.iter().any(|existing| existing == value) {
                    list.push(value.clone());
                }
            }
        }
        FuzzPubSubOp::Unsubscribe => {
            if values.is_empty() {
                list.clear();
            } else {
                list.retain(|existing| !values.iter().any(|value| value == existing));
            }
        }
    }

    Ok(())
}

fn assert_no_duplicates(values: &[String], label: &str) {
    let unique: HashSet<&str> = values.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        values.len(),
        "{label} contains duplicate subscriptions: {values:?}"
    );
}

impl NameSpec {
    fn materialize(self, index: usize) -> String {
        match self {
            Self::Empty => String::new(),
            Self::Duplicate(seed) => format!("dup-{}", seed % 4),
            Self::Unique(seed) => format!("name-{index}-{}", seed % 32),
            Self::Long(seed) => {
                let width = usize::from((seed % 12) + 4);
                let ch = char::from(b'a' + (seed % 26));
                format!("{}-{index}", ch.to_string().repeat(width))
            }
        }
    }
}
