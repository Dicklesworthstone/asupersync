#![no_main]

use arbitrary::Arbitrary;
use asupersync::distributed::{
    BudgetSnapshot, EncodedState, EncodingConfig, EncodingError, RegionSnapshot, StateEncoder,
    TaskSnapshot, TaskState,
};
use asupersync::record::region::RegionState;
use asupersync::types::{ObjectId, RegionId, TaskId, Time};
use asupersync::util::DetRng;
use libfuzzer_sys::fuzz_target;

const MAX_TASKS: usize = 16;
const MAX_CHILDREN: usize = 16;
const MAX_METADATA_LEN: usize = 4096;
const MAX_CANCEL_REASON_LEN: usize = 128;
const MAX_REPAIR_REQUEST: u16 = 8;

#[derive(Debug, Arbitrary)]
struct DistributedEncodingInput {
    seed: u64,
    object_id: u64,
    symbol_size: u16,
    min_repair_symbols: u16,
    max_source_blocks: u16,
    extra_repairs: u16,
    snapshot: SnapshotInput,
    mutation: Mutation,
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

#[derive(Debug, Arbitrary)]
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

#[derive(Debug, Arbitrary)]
enum Mutation {
    None,
    TruncateSourceBytes { drop_bytes: u16 },
    AppendSourceBytes { extra: Vec<u8> },
    DropSourceSymbol { nth: u16 },
    DuplicateSourceSymbol { nth: u16 },
    ZeroSymbolSize,
    ZeroMaxSourceBlocks,
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

fuzz_target!(|input: DistributedEncodingInput| {
    let snapshot = build_snapshot(&input.snapshot);
    let snapshot_bytes = snapshot.to_bytes();
    let config = build_config(&input);
    let mut encoder = StateEncoder::new(config.clone(), DetRng::new(input.seed));

    let encode_result = encoder.encode_with_id(
        &snapshot,
        ObjectId::new_for_test(input.object_id.wrapping_add(1)),
        Time::from_secs(input.snapshot.timestamp_secs),
    );

    match input.mutation {
        Mutation::ZeroSymbolSize => {
            let err = encode_result.expect_err("symbol_size=0 must fail");
            assert!(matches!(err, EncodingError::InvalidConfig { .. }));
        }
        Mutation::ZeroMaxSourceBlocks => {
            let err = encode_result.expect_err("max_source_blocks=0 must fail");
            assert!(matches!(err, EncodingError::InvalidConfig { .. }));
        }
        _ => {
            let encoded = encode_result.expect("valid encoding config should encode snapshot");
            assert_encoded_invariants(&encoded, &snapshot_bytes, config.symbol_size);

            let decoded = RegionSnapshot::from_bytes(&rebuild_source_bytes(&encoded))
                .expect("source-symbol reconstruction must decode");
            assert_eq!(
                decoded.to_bytes(),
                snapshot_bytes,
                "encode/rebuild/decode must round-trip exactly",
            );

            let mut repair_encoder =
                StateEncoder::new(config, DetRng::new(input.seed ^ 0xA5A5_A5A5));
            let requested_repairs = input.extra_repairs.min(MAX_REPAIR_REQUEST);
            let additional = repair_encoder
                .generate_repair(&encoded, requested_repairs)
                .expect("well-formed encodings must generate requested repairs");
            assert_eq!(additional.len(), usize::from(requested_repairs));
            assert!(
                additional.iter().all(|symbol| symbol.kind().is_repair()),
                "generate_repair must only emit repair symbols",
            );

            apply_mutation(&input.mutation, &mut repair_encoder, &encoded);
        }
    }
});

fn build_config(input: &DistributedEncodingInput) -> EncodingConfig {
    let mut symbol_size = input.symbol_size.clamp(1, 1024);
    let mut max_source_blocks = input.max_source_blocks.clamp(1, 8);

    match input.mutation {
        Mutation::ZeroSymbolSize => symbol_size = 0,
        Mutation::ZeroMaxSourceBlocks => max_source_blocks = 0,
        _ => {}
    }

    EncodingConfig {
        symbol_size,
        min_repair_symbols: input.min_repair_symbols.min(MAX_REPAIR_REQUEST),
        max_source_blocks,
        repair_overhead: 1.25,
    }
}

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

fn assert_encoded_invariants(encoded: &EncodedState, snapshot_bytes: &[u8], symbol_size: u16) {
    assert_eq!(
        encoded.symbols.len(),
        usize::from(encoded.source_count) + usize::from(encoded.repair_count),
        "source_count + repair_count must match total symbol vector length",
    );
    assert_eq!(
        rebuild_source_bytes(encoded),
        snapshot_bytes,
        "ordered source symbols must reconstruct the original serialized snapshot bytes",
    );
    for symbol in &encoded.symbols {
        assert!(
            symbol.data().len() <= usize::from(symbol_size),
            "symbol length {} exceeds configured symbol_size {}",
            symbol.data().len(),
            symbol_size,
        );
    }
}

fn rebuild_source_bytes(encoded: &EncodedState) -> Vec<u8> {
    let mut sources: Vec<_> = encoded.source_symbols().collect();
    sources.sort_by_key(|symbol| (symbol.id().sbn(), symbol.id().esi()));
    let mut data = Vec::with_capacity(encoded.original_size);
    for symbol in sources {
        data.extend_from_slice(symbol.data());
    }
    data.truncate(encoded.original_size);
    data
}

fn apply_mutation(mutation: &Mutation, encoder: &mut StateEncoder, encoded: &EncodedState) {
    match mutation {
        Mutation::None | Mutation::ZeroSymbolSize | Mutation::ZeroMaxSourceBlocks => {}
        Mutation::TruncateSourceBytes { drop_bytes } => {
            let mut bytes = rebuild_source_bytes(encoded);
            let drop = 1 + usize::from(*drop_bytes) % bytes.len();
            bytes.truncate(bytes.len() - drop);
            assert!(
                RegionSnapshot::from_bytes(&bytes).is_err(),
                "truncated source byte stream must fail closed",
            );
        }
        Mutation::AppendSourceBytes { extra } => {
            let mut bytes = rebuild_source_bytes(encoded);
            let tail: Vec<u8> = extra.iter().copied().take(128).collect();
            if !tail.is_empty() {
                bytes.extend_from_slice(&tail);
                assert!(
                    RegionSnapshot::from_bytes(&bytes).is_err(),
                    "trailing bytes after a serialized snapshot must be rejected",
                );
            }
        }
        Mutation::DropSourceSymbol { nth } => {
            let source_index = usize::from(*nth);
            let maybe_missing = encoded
                .source_symbols()
                .nth(source_index)
                .map(|symbol| symbol.id());
            if let Some(missing) = maybe_missing {
                let degraded = EncodedState {
                    params: encoded.params,
                    symbols: encoded
                        .symbols
                        .iter()
                        .filter(|symbol| symbol.id() != missing)
                        .cloned()
                        .collect(),
                    source_count: encoded.source_count,
                    repair_count: encoded.repair_count,
                    original_size: encoded.original_size,
                    encoded_at: encoded.encoded_at,
                };
                assert!(
                    encoder.generate_repair(&degraded, 1).is_err(),
                    "missing source symbols must block repair generation",
                );
            }
        }
        Mutation::DuplicateSourceSymbol { nth } => {
            if let Some(duplicate) = encoded.source_symbols().nth(usize::from(*nth)).cloned() {
                let mut symbols = encoded.symbols.clone();
                symbols.push(duplicate);
                let malformed = EncodedState {
                    params: encoded.params,
                    symbols,
                    source_count: encoded.source_count,
                    repair_count: encoded.repair_count,
                    original_size: encoded.original_size,
                    encoded_at: encoded.encoded_at,
                };
                assert!(
                    encoder.generate_repair(&malformed, 1).is_err(),
                    "duplicate source symbols must block repair generation",
                );
            }
        }
    }
}
