//! Fuzz target for distributed recovery decode and trigger validation.
//!
//! Exercises the missing end-to-end seam between
//! `StateDecoder::decode_snapshot` and `RecoveryOrchestrator::recover_from_symbols`
//! using real `ObjectParams` plus source-symbol streams. The target covers:
//! - unsupported/random snapshot version bytes
//! - malformed metadata length prefixes
//! - partial/truncated snapshot payloads
//! - invalid snapshot state bytes
//! - trigger validation mismatches for region and sequence floors
//!
//! The key invariant is that malformed payloads must fail closed with an
//! error, while valid payloads may only fail at the trigger-validation stage.
//! Run with:
//! `cargo fuzz run fuzz_distributed_recovery_decode -- -max_total_time=60`

#![no_main]

use arbitrary::Arbitrary;
use asupersync::distributed::{
    BudgetSnapshot, CollectedSymbol, RecoveryConfig, RecoveryDecodingConfig, RecoveryOrchestrator,
    RecoveryTrigger, RegionSnapshot, StateDecoder, TaskSnapshot, TaskState,
};
use asupersync::error::{Error, ErrorKind};
use asupersync::record::region::RegionState;
use asupersync::security::AuthenticatedSymbol;
use asupersync::security::tag::AuthenticationTag;
use asupersync::types::symbol::{ObjectId, ObjectParams, Symbol};
use asupersync::types::{RegionId, TaskId, Time};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

const MAX_TASKS: usize = 8;
const MAX_CHILDREN: usize = 8;
const MAX_METADATA_LEN: usize = 512;
const MAX_CANCEL_REASON_LEN: usize = 64;
const MAX_SYMBOL_SIZE: u16 = 256;
const REPLICA_NAMES: [&str; 4] = ["r0", "r1", "r2", "r3"];

#[derive(Debug, Arbitrary)]
struct RecoveryDecodeInput {
    object_id: u64,
    symbol_size: u16,
    snapshot: SnapshotInput,
    payload_mutation: PayloadMutation,
    trigger_case: TriggerCase,
}

#[derive(Debug, Arbitrary)]
struct SnapshotInput {
    region_index: u32,
    region_generation: u32,
    state: RegionStateInput,
    timestamp_secs: u64,
    sequence: u64,
    tasks: Vec<TaskInput>,
    children: Vec<RegionInput>,
    finalizer_count: u32,
    deadline_nanos: Option<u64>,
    polls_remaining: Option<u32>,
    cost_remaining: Option<u64>,
    cancel_reason: Option<String>,
    parent: Option<RegionInput>,
    metadata: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum RegionStateInput {
    Open,
    Closing,
    Draining,
    Finalizing,
    Closed,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum TaskStateInput {
    Pending,
    Running,
    Completed,
    Cancelled,
    Panicked,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
struct TaskInput {
    index: u32,
    generation: u32,
    state: TaskStateInput,
    priority: u8,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
struct RegionInput {
    index: u32,
    generation: u32,
}

#[derive(Debug, Clone, Arbitrary)]
enum PayloadMutation {
    None,
    UnsupportedVersion { version: u8 },
    InvalidMetadataLength { extra: u16 },
    Truncate { drop_bytes: u16 },
    InvalidState { state_byte: u8 },
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum TriggerCase {
    MatchingManual,
    RegionMismatch,
    RestartSequenceAhead { delta: u16 },
    InconsistencyFloorAhead { local_delta: u16, remote_delta: u16 },
}

impl RegionStateInput {
    fn into_region_state(self) -> RegionState {
        match self {
            Self::Open => RegionState::Open,
            Self::Closing => RegionState::Closing,
            Self::Draining => RegionState::Draining,
            Self::Finalizing => RegionState::Finalizing,
            Self::Closed => RegionState::Closed,
        }
    }
}

impl TaskStateInput {
    fn into_task_state(self) -> TaskState {
        match self {
            Self::Pending => TaskState::Pending,
            Self::Running => TaskState::Running,
            Self::Completed => TaskState::Completed,
            Self::Cancelled => TaskState::Cancelled,
            Self::Panicked => TaskState::Panicked,
        }
    }
}

impl RegionInput {
    fn into_region_id(self) -> RegionId {
        RegionId::new_for_test(self.index, self.generation)
    }
}

fuzz_target!(|input: RecoveryDecodeInput| {
    let snapshot = build_snapshot(&input.snapshot);
    let expected_bytes = snapshot.to_bytes();
    let (payload_bytes, payload_is_valid) =
        mutate_payload(&snapshot, &expected_bytes, &input.payload_mutation);

    let symbol_size = input.symbol_size.clamp(8, MAX_SYMBOL_SIZE);
    let object_id = ObjectId::new_for_test(input.object_id);
    let params = object_params_for_payload(object_id, &payload_bytes, symbol_size);
    let symbols = symbols_for_payload(object_id, symbol_size, &payload_bytes);
    let trigger = build_trigger(&snapshot, input.trigger_case);
    let trigger_is_valid = matches!(input.trigger_case, TriggerCase::MatchingManual);

    let direct_decode = decode_snapshot(&symbols, &params);
    if payload_is_valid {
        let recovered = direct_decode.expect("valid payload must decode through StateDecoder");
        assert_eq!(
            recovered.to_bytes(),
            expected_bytes,
            "valid recovery decode must preserve canonical snapshot bytes",
        );
    } else {
        let err = direct_decode.expect_err("malformed snapshot payload must not decode");
        assert_eq!(
            err.kind(),
            ErrorKind::DecodingFailed,
            "malformed snapshot payload must fail at decode_snapshot",
        );
    }

    let collected = collected_symbols(&symbols);
    let mut orchestrator =
        RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());
    let orchestrated =
        orchestrator.recover_from_symbols(&trigger, &collected, params, Duration::from_millis(1));

    match (payload_is_valid, trigger_is_valid) {
        (true, true) => {
            let result = orchestrated.expect("valid payload and trigger must recover");
            assert_eq!(
                result.snapshot.to_bytes(),
                expected_bytes,
                "orchestrated recovery must preserve canonical snapshot bytes",
            );
        }
        (true, false) => {
            let err = orchestrated.expect_err("trigger mismatch must fail recovery");
            assert_eq!(err.kind(), ErrorKind::RecoveryFailed);
            assert!(
                err.to_string().contains("trigger region")
                    || err.to_string().contains("older than"),
                "unexpected trigger validation error: {err}",
            );
        }
        (false, _) => {
            let err = orchestrated.expect_err("malformed payload must fail orchestrated recovery");
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::DecodingFailed | ErrorKind::RecoveryFailed
                ),
                "unexpected malformed-payload error kind: {err}",
            );
        }
    }
});

fn build_snapshot(input: &SnapshotInput) -> RegionSnapshot {
    RegionSnapshot {
        region_id: RegionId::new_for_test(input.region_index, input.region_generation),
        state: input.state.into_region_state(),
        timestamp: Time::from_secs(input.timestamp_secs),
        sequence: input.sequence,
        tasks: input
            .tasks
            .iter()
            .take(MAX_TASKS)
            .map(|task| TaskSnapshot {
                task_id: TaskId::new_for_test(task.index, task.generation),
                state: task.state.into_task_state(),
                priority: task.priority,
            })
            .collect(),
        children: input
            .children
            .iter()
            .copied()
            .take(MAX_CHILDREN)
            .map(RegionInput::into_region_id)
            .collect(),
        finalizer_count: input.finalizer_count,
        budget: BudgetSnapshot {
            deadline_nanos: input.deadline_nanos,
            polls_remaining: input.polls_remaining,
            cost_remaining: input.cost_remaining,
        },
        cancel_reason: input
            .cancel_reason
            .as_ref()
            .map(|reason| reason.chars().take(MAX_CANCEL_REASON_LEN).collect()),
        parent: input.parent.map(RegionInput::into_region_id),
        metadata: input
            .metadata
            .iter()
            .copied()
            .take(MAX_METADATA_LEN)
            .collect(),
    }
}

fn mutate_payload(
    snapshot: &RegionSnapshot,
    canonical: &[u8],
    mutation: &PayloadMutation,
) -> (Vec<u8>, bool) {
    let mut bytes = canonical.to_vec();
    match mutation {
        PayloadMutation::None => (bytes, true),
        PayloadMutation::UnsupportedVersion { version } => {
            let invalid_version = if *version == 1 { 2 } else { *version };
            if let Some(slot) = bytes.get_mut(4) {
                *slot = invalid_version;
            }
            (bytes, false)
        }
        PayloadMutation::InvalidMetadataLength { extra } => {
            let offset = bytes
                .len()
                .saturating_sub(snapshot.metadata.len())
                .saturating_sub(4);
            if offset + 4 <= bytes.len() {
                let declared = u32::try_from(snapshot.metadata.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(u32::from((*extra).max(1)));
                bytes[offset..offset + 4].copy_from_slice(&declared.to_le_bytes());
            }
            (bytes, false)
        }
        PayloadMutation::Truncate { drop_bytes } => {
            let len = bytes.len();
            if len > 0 {
                let max_drop = len.saturating_sub(1);
                let drop = usize::from(*drop_bytes).min(max_drop).max(1);
                bytes.truncate(len - drop);
            }
            (bytes, false)
        }
        PayloadMutation::InvalidState { state_byte } => {
            let state_offset = 13;
            if let Some(slot) = bytes.get_mut(state_offset) {
                *slot = if *state_byte <= 4 { 0xFF } else { *state_byte };
            }
            (bytes, false)
        }
    }
}

fn object_params_for_payload(
    object_id: ObjectId,
    payload: &[u8],
    symbol_size: u16,
) -> ObjectParams {
    let object_size = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let symbols_per_block = if payload.is_empty() {
        0
    } else {
        let rounded = payload.len().div_ceil(usize::from(symbol_size));
        u16::try_from(rounded).unwrap_or(u16::MAX)
    };
    ObjectParams::new(object_id, object_size, symbol_size, 1, symbols_per_block)
}

fn symbols_for_payload(object_id: ObjectId, symbol_size: u16, payload: &[u8]) -> Vec<Symbol> {
    payload
        .chunks(usize::from(symbol_size))
        .enumerate()
        .map(|(esi, chunk)| {
            Symbol::new_for_test(
                object_id.as_u128() as u64,
                0,
                u32::try_from(esi).unwrap_or(u32::MAX),
                chunk,
            )
        })
        .collect()
}

fn decode_snapshot(symbols: &[Symbol], params: &ObjectParams) -> Result<RegionSnapshot, Error> {
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
    for symbol in symbols {
        let auth = AuthenticatedSymbol::from_parts(symbol.clone(), AuthenticationTag::zero());
        decoder.add_symbol(&auth)?;
    }
    decoder.decode_snapshot(params)
}

fn collected_symbols(symbols: &[Symbol]) -> Vec<CollectedSymbol> {
    symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| CollectedSymbol {
            symbol: symbol.clone(),
            tag: AuthenticationTag::zero(),
            source_replica: REPLICA_NAMES[index % REPLICA_NAMES.len()].to_owned(),
            collected_at: Time::from_secs(u64::try_from(index).unwrap_or(u64::MAX)),
            verified: false,
        })
        .collect()
}

fn build_trigger(snapshot: &RegionSnapshot, trigger_case: TriggerCase) -> RecoveryTrigger {
    match trigger_case {
        TriggerCase::MatchingManual => RecoveryTrigger::ManualTrigger {
            region_id: snapshot.region_id,
            initiator: "fuzz".to_string(),
            reason: Some("valid trigger".to_string()),
        },
        TriggerCase::RegionMismatch => RecoveryTrigger::ManualTrigger {
            region_id: RegionId::new_for_test(
                snapshot.region_id.arena_index().index().wrapping_add(1),
                snapshot.region_id.arena_index().generation(),
            ),
            initiator: "fuzz".to_string(),
            reason: Some("region mismatch".to_string()),
        },
        TriggerCase::RestartSequenceAhead { delta } => RecoveryTrigger::NodeRestart {
            region_id: snapshot.region_id,
            last_known_sequence: snapshot.sequence.saturating_add(u64::from(delta.max(1))),
        },
        TriggerCase::InconsistencyFloorAhead {
            local_delta,
            remote_delta,
        } => RecoveryTrigger::InconsistencyDetected {
            region_id: snapshot.region_id,
            local_sequence: snapshot
                .sequence
                .saturating_add(u64::from(local_delta.max(1))),
            remote_sequence: snapshot
                .sequence
                .saturating_add(u64::from(remote_delta.max(1))),
        },
    }
}
