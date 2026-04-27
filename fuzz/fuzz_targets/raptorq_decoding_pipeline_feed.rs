//! Structure-aware fuzz target for `DecodingPipeline::feed()`.
//!
//! This target complements the lower-level RaptorQ decoder fuzzers by
//! exercising the public authenticated-symbol entry point directly.
//!
//! Coverage goals:
//! - random object sizes across single- and multi-block layouts
//! - FEC payload-id drift via `SBN` / `ESI` mutation
//! - symbol-size and corrupted-payload rejection paths
//! - auth integration for strict, permissive, disabled, and no-context modes
//! - per-block memory-limit rejection without panics or hangs
//!
//! Run with:
//! cargo +nightly fuzz run raptorq_decoding_pipeline_feed -- -max_total_time=300

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::config::EncodingConfig;
use asupersync::decoding::{DecodingConfig, DecodingPipeline, RejectReason, SymbolAcceptResult};
use asupersync::encoding::{EncodingError, EncodingPipeline};
use asupersync::security::{
    AuthMode, AuthenticatedSymbol, SecurityContext, tag::AuthenticationTag,
};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};

const MAX_K: usize = 1024;
const MAX_BLOCKS: usize = 4;
const MAX_SYMBOL_SIZE: usize = 64;
const MAX_REPAIR_SYMBOLS: usize = 8;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Arbitrary, Debug)]
struct FeedFuzzInput {
    object_seed: u128,
    auth_seed: u64,
    payload_bytes: Vec<u8>,
    object_size_hint: u32,
    target_k: u16,
    symbol_size: u8,
    source_blocks: u8,
    repair_symbols: u8,
    auth_mode: AuthModeChoice,
    buffer_budget: BufferBudget,
    symbol_mode: SymbolMode,
    reorder: ReorderMode,
    target_index: u16,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum AuthModeChoice {
    DisabledUnsigned,
    DisabledSigned,
    StrictNoContext,
    StrictValid,
    StrictWrongKey,
    PermissiveWrongKey,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum BufferBudget {
    Default,
    Tight { limit: u8 },
}

#[derive(Arbitrary, Debug, Clone, PartialEq, Eq)]
enum SymbolMode {
    None,
    Duplicate,
    WrongObjectId,
    OutOfLayoutSbn,
    SourceEsiOutOfRange,
    RepairEsiOverflow,
    TruncatePayload { keep: u8 },
    FlipPayload { offset: u16, mask: u8 },
    ToggleKind,
    CorruptTag,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum ReorderMode {
    Preserve,
    Reverse,
    Rotate,
}

#[derive(Clone, Copy, Debug)]
struct BlockPlanLite {
    k: usize,
}

fuzz_target!(|input: FeedFuzzInput| {
    let mut input = input;
    normalize(&mut input);
    execute(input);
});

fn normalize(input: &mut FeedFuzzInput) {
    input.payload_bytes.truncate(MAX_PAYLOAD_BYTES);
    input.target_k = ((usize::from(input.target_k) % MAX_K) + 1) as u16;
    input.symbol_size = ((usize::from(input.symbol_size) % MAX_SYMBOL_SIZE) + 1) as u8;
    input.source_blocks = ((usize::from(input.source_blocks) % MAX_BLOCKS) + 1) as u8;
    input.repair_symbols = (usize::from(input.repair_symbols) % (MAX_REPAIR_SYMBOLS + 1)) as u8;

    if matches!(input.buffer_budget, BufferBudget::Tight { .. }) && input.target_k < 2 {
        input.target_k = 2;
    }
}

fn execute(input: FeedFuzzInput) {
    let symbol_size = u16::from(input.symbol_size);
    let max_block_size = usize::from(input.target_k) * usize::from(symbol_size);
    if max_block_size == 0 {
        return;
    }

    let total_capacity = max_block_size * usize::from(input.source_blocks);
    let object_size = 1 + (input.object_size_hint as usize % total_capacity.max(1));
    let object_id = ObjectId::from_u128(input.object_seed);
    let payload = build_payload(object_size, input.auth_seed, &input.payload_bytes);
    let plans = plan_blocks(object_size, usize::from(symbol_size), max_block_size);
    let params = ObjectParams::new(
        object_id,
        object_size as u64,
        symbol_size,
        plans.len() as u16,
        plans.iter().map(|plan| plan.k).max().unwrap_or(0) as u16,
    );

    let repair_symbols = effective_repair_count(input.symbol_mode.clone(), input.repair_symbols);
    let mut encoder = EncodingPipeline::new(
        EncodingConfig {
            symbol_size,
            max_block_size,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        SymbolPool::new(PoolConfig::default()),
    );

    let encoded_symbols = match encoder
        .encode_with_repair(object_id, &payload, repair_symbols)
        .collect::<Result<Vec<_>, EncodingError>>()
    {
        Ok(symbols) => symbols
            .into_iter()
            .map(|encoded| encoded.into_symbol())
            .collect::<Vec<_>>(),
        Err(EncodingError::InvalidConfig { .. }) | Err(EncodingError::DataTooLarge { .. }) => {
            return;
        }
        Err(other) => panic!("unexpected encode failure for normalized input: {other:?}"),
    };

    let mut symbols = encoded_symbols;
    apply_reorder(&mut symbols, input.reorder, input.target_index);
    apply_symbol_mutation(&mut symbols, &input.symbol_mode, input.target_index, params);

    let mut pipeline = make_pipeline(
        input.auth_mode,
        input.auth_seed,
        symbol_size,
        max_block_size,
        input.buffer_budget,
    );
    pipeline
        .set_object_params(params)
        .expect("normalized object params should be accepted");

    let signing_ctx = SecurityContext::for_testing(input.auth_seed);
    let configured_limit = configured_max_buffered_symbols(input.buffer_budget);
    let mut saw_duplicate = false;
    let mut saw_wrong_object = false;
    let mut saw_auth_failed = false;
    let mut saw_size_mismatch = false;
    let mut saw_invalid_metadata = false;
    let mut saw_memory_limit = false;

    for symbol in symbols {
        let auth_symbol = wrap_symbol(
            symbol,
            &signing_ctx,
            input.auth_mode,
            &input.symbol_mode,
            input.target_index,
        );

        let result = pipeline.feed(auth_symbol);
        let accept = match result {
            Ok(accept) => accept,
            Err(err) => panic!("normalized fuzz input produced pipeline error: {err:?}"),
        };

        match accept {
            SymbolAcceptResult::Accepted { .. }
            | SymbolAcceptResult::DecodingStarted { .. }
            | SymbolAcceptResult::BlockComplete { .. } => {}
            SymbolAcceptResult::Duplicate => saw_duplicate = true,
            SymbolAcceptResult::Rejected(RejectReason::WrongObjectId) => saw_wrong_object = true,
            SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => {
                saw_auth_failed = true;
            }
            SymbolAcceptResult::Rejected(RejectReason::SymbolSizeMismatch) => {
                saw_size_mismatch = true;
            }
            SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata)
            | SymbolAcceptResult::Rejected(RejectReason::InconsistentEquations) => {
                saw_invalid_metadata = true;
            }
            SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached) => {
                saw_memory_limit = true;
            }
            SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded)
            | SymbolAcceptResult::Rejected(RejectReason::InsufficientRank) => {}
        }
    }

    match input.auth_mode {
        AuthModeChoice::StrictNoContext | AuthModeChoice::StrictWrongKey => {
            assert!(saw_auth_failed, "strict auth mismatch should be rejected");
            assert!(
                !pipeline.is_complete(),
                "strict auth rejection should prevent completion"
            );
        }
        AuthModeChoice::PermissiveWrongKey => {
            assert!(
                !saw_auth_failed,
                "permissive auth mode should not hard-reject mismatched tags"
            );
        }
        AuthModeChoice::DisabledUnsigned
        | AuthModeChoice::DisabledSigned
        | AuthModeChoice::StrictValid => {}
    }

    match input.symbol_mode {
        SymbolMode::Duplicate => assert!(saw_duplicate, "duplicate symbol should be reported"),
        SymbolMode::WrongObjectId => {
            assert!(saw_wrong_object, "wrong-object symbol should be rejected")
        }
        SymbolMode::OutOfLayoutSbn
        | SymbolMode::SourceEsiOutOfRange
        | SymbolMode::RepairEsiOverflow
        | SymbolMode::ToggleKind => {
            assert!(saw_invalid_metadata, "metadata mutation should be rejected");
        }
        SymbolMode::TruncatePayload { .. } => {
            assert!(saw_size_mismatch, "truncated symbol should be rejected");
        }
        SymbolMode::CorruptTag => {
            if matches!(
                input.auth_mode,
                AuthModeChoice::StrictValid
                    | AuthModeChoice::StrictWrongKey
                    | AuthModeChoice::StrictNoContext
            ) {
                assert!(saw_auth_failed, "strict mode should reject a corrupted tag");
            }
        }
        SymbolMode::None | SymbolMode::FlipPayload { .. } => {}
    }

    let should_hit_memory_limit = matches!(input.buffer_budget, BufferBudget::Tight { .. })
        && plans.iter().any(|plan| plan.k > configured_limit);
    if should_hit_memory_limit && !pipeline.is_complete() {
        assert!(
            saw_memory_limit || saw_auth_failed,
            "tight budgets should either hit the buffer cap or fail earlier on auth"
        );
    }

    if pipeline.is_complete() {
        let decoded = pipeline
            .into_data()
            .expect("complete pipeline should yield decoded object");
        if symbol_mode_preserves_payload(&input.symbol_mode) {
            assert_eq!(decoded, payload, "decoded payload drifted from original");
        }
    } else {
        let _ = pipeline.into_data().err();
    }
}

fn build_payload(object_size: usize, seed: u64, payload_bytes: &[u8]) -> Vec<u8> {
    let salt = seed.to_le_bytes();
    let mut payload = Vec::with_capacity(object_size);
    for idx in 0..object_size {
        let patterned = ((idx * 29 + 0x5A) & 0xFF) as u8;
        let mixed = if payload_bytes.is_empty() {
            patterned ^ salt[idx % salt.len()] ^ ((idx >> 3) as u8)
        } else {
            let src = payload_bytes[idx % payload_bytes.len()];
            src ^ patterned ^ salt[(idx + src as usize) % salt.len()]
        };
        payload.push(mixed);
    }
    payload
}

fn plan_blocks(
    object_size: usize,
    symbol_size: usize,
    max_block_size: usize,
) -> Vec<BlockPlanLite> {
    let mut remaining = object_size;
    let mut plans = Vec::new();
    while remaining > 0 {
        let len = remaining.min(max_block_size);
        plans.push(BlockPlanLite {
            k: len.div_ceil(symbol_size),
        });
        remaining -= len;
    }
    plans
}

fn effective_repair_count(mode: SymbolMode, repair_symbols: u8) -> usize {
    let base = usize::from(repair_symbols);
    match mode {
        SymbolMode::RepairEsiOverflow | SymbolMode::WrongObjectId => base.max(1),
        _ => base,
    }
}

fn make_pipeline(
    auth_mode: AuthModeChoice,
    auth_seed: u64,
    symbol_size: u16,
    max_block_size: usize,
    buffer_budget: BufferBudget,
) -> DecodingPipeline {
    let max_buffered_symbols = match buffer_budget {
        BufferBudget::Default => 8192,
        BufferBudget::Tight { limit } => usize::from(limit % 4) + 1,
    };
    let base_config = DecodingConfig {
        symbol_size,
        max_block_size,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols,
        block_timeout: std::time::Duration::from_secs(30),
        verify_auth: !matches!(
            auth_mode,
            AuthModeChoice::DisabledUnsigned | AuthModeChoice::DisabledSigned
        ),
    };

    match auth_mode {
        AuthModeChoice::DisabledUnsigned
        | AuthModeChoice::DisabledSigned
        | AuthModeChoice::StrictNoContext => DecodingPipeline::new(base_config),
        AuthModeChoice::StrictValid => {
            DecodingPipeline::with_auth(base_config, SecurityContext::for_testing(auth_seed))
        }
        AuthModeChoice::StrictWrongKey => DecodingPipeline::with_auth(
            base_config,
            SecurityContext::for_testing(auth_seed.wrapping_add(1)),
        ),
        AuthModeChoice::PermissiveWrongKey => DecodingPipeline::with_auth(
            base_config,
            SecurityContext::for_testing_with_mode(auth_seed.wrapping_add(1), AuthMode::Permissive),
        ),
    }
}

fn configured_max_buffered_symbols(buffer_budget: BufferBudget) -> usize {
    match buffer_budget {
        BufferBudget::Default => 8192,
        BufferBudget::Tight { limit } => usize::from(limit % 4) + 1,
    }
}

fn apply_reorder(symbols: &mut [Symbol], reorder: ReorderMode, target_index: u16) {
    match reorder {
        ReorderMode::Preserve => {}
        ReorderMode::Reverse => symbols.reverse(),
        ReorderMode::Rotate => {
            if !symbols.is_empty() {
                symbols.rotate_left(usize::from(target_index) % symbols.len());
            }
        }
    }
}

fn apply_symbol_mutation(
    symbols: &mut Vec<Symbol>,
    mode: &SymbolMode,
    target_index: u16,
    params: ObjectParams,
) {
    if symbols.is_empty() {
        return;
    }

    let idx = usize::from(target_index) % symbols.len();
    let target = symbols[idx].clone();

    match mode {
        SymbolMode::None | SymbolMode::CorruptTag => {}
        SymbolMode::Duplicate => symbols.push(target),
        SymbolMode::WrongObjectId => {
            symbols[idx] = Symbol::new(
                SymbolId::new(
                    ObjectId::from_u128(target.object_id().as_u128().wrapping_add(1)),
                    target.sbn(),
                    target.esi(),
                ),
                target.data().to_vec(),
                target.kind(),
            );
        }
        SymbolMode::OutOfLayoutSbn => {
            symbols[idx] = Symbol::new(
                SymbolId::new(target.object_id(), params.source_blocks as u8, target.esi()),
                target.data().to_vec(),
                target.kind(),
            );
        }
        SymbolMode::SourceEsiOutOfRange => {
            symbols[idx] = Symbol::new(
                SymbolId::new(
                    target.object_id(),
                    target.sbn(),
                    u32::from(params.symbols_per_block),
                ),
                target.data().to_vec(),
                SymbolKind::Source,
            );
        }
        SymbolMode::RepairEsiOverflow => {
            symbols[idx] = Symbol::new(
                SymbolId::new(target.object_id(), target.sbn(), u32::MAX),
                target.data().to_vec(),
                SymbolKind::Repair,
            );
        }
        SymbolMode::TruncatePayload { keep } => {
            let keep = usize::from(*keep) % target.len().saturating_add(1);
            symbols[idx] = Symbol::new(target.id(), target.data()[..keep].to_vec(), target.kind());
        }
        SymbolMode::FlipPayload { offset, mask } => {
            let mut data = target.data().to_vec();
            if !data.is_empty() {
                let byte = usize::from(*offset) % data.len();
                data[byte] ^= *mask;
            }
            symbols[idx] = Symbol::new(target.id(), data, target.kind());
        }
        SymbolMode::ToggleKind => {
            let kind = match target.kind() {
                SymbolKind::Source => SymbolKind::Repair,
                SymbolKind::Repair => SymbolKind::Source,
            };
            symbols[idx] = Symbol::new(target.id(), target.data().to_vec(), kind);
        }
    }
}

fn wrap_symbol(
    symbol: Symbol,
    signing_ctx: &SecurityContext,
    auth_mode: AuthModeChoice,
    symbol_mode: &SymbolMode,
    target_index: u16,
) -> AuthenticatedSymbol {
    let mut auth = match auth_mode {
        AuthModeChoice::DisabledUnsigned | AuthModeChoice::StrictNoContext => {
            AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero())
        }
        AuthModeChoice::DisabledSigned
        | AuthModeChoice::StrictValid
        | AuthModeChoice::StrictWrongKey
        | AuthModeChoice::PermissiveWrongKey => signing_ctx.sign_symbol(&symbol),
    };

    if matches!(symbol_mode, SymbolMode::CorruptTag) {
        let _ = target_index;
        auth = AuthenticatedSymbol::from_parts(auth.into_symbol(), AuthenticationTag::zero());
    }

    auth
}

fn symbol_mode_preserves_payload(mode: &SymbolMode) -> bool {
    matches!(
        mode,
        SymbolMode::None
            | SymbolMode::Duplicate
            | SymbolMode::WrongObjectId
            | SymbolMode::OutOfLayoutSbn
            | SymbolMode::SourceEsiOutOfRange
            | SymbolMode::RepairEsiOverflow
            | SymbolMode::ToggleKind
            | SymbolMode::CorruptTag
    )
}
