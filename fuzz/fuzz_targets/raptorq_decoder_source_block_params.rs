//! Structure-aware fuzz target for RaptorQ decoder block/layout parameters.
//!
//! Existing RaptorQ fuzzers cover low-level decoder equations, matrix paths,
//! and generic round-trip behavior. This target focuses on a missing surface:
//! `DecodingPipeline` object/block metadata and symbol identity combinations.
//!
//! Coverage goals:
//! - high-`K` blocks (`K >= 2048`) with tiny symbol sizes (`T = 1`)
//! - multi-block `SBN` routing and out-of-layout block rejection
//! - `ESI` edge cases (`source ESI >= K`, `repair ESI` overflow)
//! - `ObjectParams` drift (`source_blocks`, `symbols_per_block`, `symbol_size`)
//! - successful decode invariants under reordering and duplicate symbol delivery

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::config::EncodingConfig;
use asupersync::decoding::{
    DecodingConfig, DecodingError, DecodingPipeline, RejectReason, SymbolAcceptResult,
};
use asupersync::encoding::{EncodingError, EncodingPipeline};
use asupersync::security::{tag::AuthenticationTag, AuthenticatedSymbol};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};

const MAX_K: usize = 4096;
const MAX_BLOCKS: usize = 4;
const MAX_SYMBOL_SIZE: usize = 16;
const MAX_REPAIR_SYMBOLS: usize = 4;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    object_seed: u64,
    payload_seed: u64,
    target_k: u16,
    symbol_size: u8,
    source_blocks: u8,
    tail_trim: u16,
    repair_symbols: u8,
    param_mode: ParamMode,
    symbol_mode: SymbolMode,
    reorder: ReorderMode,
    target_index: u16,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum ParamMode {
    Exact,
    WrongBlockCount,
    WrongSymbolsPerBlock,
    WrongSymbolSize,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolMode {
    None,
    Duplicate,
    OutOfLayoutSbn,
    RepairEsiOverflow,
    SourceEsiOutOfRange,
    WrongObjectId,
    TruncatePayload,
    ToggleKind,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum ReorderMode {
    Preserve,
    Reverse,
    Rotate,
}

#[derive(Clone, Copy)]
struct BlockPlanLite {
    k: usize,
}

fuzz_target!(|input: FuzzInput| {
    let mut input = input;
    normalize(&mut input);
    execute(input);
});

fn normalize(input: &mut FuzzInput) {
    input.target_k = ((usize::from(input.target_k) % MAX_K) + 1) as u16;
    input.symbol_size = ((usize::from(input.symbol_size) % MAX_SYMBOL_SIZE) + 1) as u8;
    input.source_blocks = ((usize::from(input.source_blocks) % MAX_BLOCKS) + 1) as u8;
    input.repair_symbols = (usize::from(input.repair_symbols) % (MAX_REPAIR_SYMBOLS + 1)) as u8;
}

fn execute(input: FuzzInput) {
    let symbol_size = u16::from(input.symbol_size);
    let max_block_size = usize::from(input.target_k) * usize::from(symbol_size);
    if max_block_size == 0 {
        return;
    }

    let total_capacity = max_block_size * usize::from(input.source_blocks);
    let tail_trim = usize::from(input.tail_trim) % max_block_size;
    let object_size = total_capacity.saturating_sub(tail_trim).max(1);
    let object_id = ObjectId::new_for_test(input.object_seed);
    let payload = build_payload(object_size, input.payload_seed);
    let plans = plan_blocks(object_size, usize::from(symbol_size), max_block_size);
    let exact_params = ObjectParams::new(
        object_id,
        object_size as u64,
        symbol_size,
        plans.len() as u16,
        plans.iter().map(|plan| plan.k).max().unwrap_or(0) as u16,
    );

    let repair_symbols = effective_repair_count(input.symbol_mode, input.repair_symbols);
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
            // Unsupported high-K layouts are still valid fuzz inputs; the encoder
            // rejecting them cleanly is already an acceptable outcome.
            return;
        }
        Err(other) => panic!("unexpected encode failure for normalized input: {other:?}"),
    };

    let mut pipeline = make_pipeline(symbol_size, max_block_size);
    let declared_params = mutate_params(exact_params, input.param_mode);

    match pipeline.set_object_params(declared_params) {
        Ok(()) => {
            assert_eq!(
                input.param_mode,
                ParamMode::Exact,
                "metadata drift should not be accepted: {:?}",
                input.param_mode
            );
        }
        Err(err) => {
            assert!(
                matches!(
                    err,
                    DecodingError::InconsistentMetadata { .. }
                        | DecodingError::SymbolSizeMismatch { .. }
                ),
                "unexpected metadata error: {err:?}"
            );
            if input.param_mode == ParamMode::Exact {
                panic!("exact params unexpectedly rejected: {err:?}");
            }

            // Invalid params must not poison a subsequent valid declaration.
            let mut retry = make_pipeline(symbol_size, max_block_size);
            retry
                .set_object_params(exact_params)
                .expect("valid params should still be accepted after failed declaration");
            return;
        }
    }

    let mut symbols = encoded_symbols;
    apply_reorder(&mut symbols, input.reorder, input.target_index);
    apply_symbol_mutation(
        &mut symbols,
        input.symbol_mode,
        input.target_index,
        exact_params,
    );

    let mut saw_wrong_object = false;
    let mut saw_symbol_size_mismatch = false;
    let mut saw_invalid_metadata = false;

    for symbol in symbols {
        let result = pipeline.feed(AuthenticatedSymbol::from_parts(
            symbol,
            AuthenticationTag::zero(),
        ));

        let accept = match result {
            Ok(accept) => accept,
            Err(err) => panic!("normalized fuzz input produced pipeline error: {err:?}"),
        };

        match accept {
            SymbolAcceptResult::Rejected(RejectReason::WrongObjectId) => saw_wrong_object = true,
            SymbolAcceptResult::Rejected(RejectReason::SymbolSizeMismatch) => {
                saw_symbol_size_mismatch = true;
            }
            SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata) => {
                saw_invalid_metadata = true;
            }
            SymbolAcceptResult::BlockComplete { .. }
            | SymbolAcceptResult::Accepted { .. }
            | SymbolAcceptResult::DecodingStarted { .. }
            | SymbolAcceptResult::Duplicate
            | SymbolAcceptResult::Rejected(RejectReason::InsufficientRank)
            | SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached)
            | SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded)
            | SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => {}
        }
    }

    match input.symbol_mode {
        SymbolMode::WrongObjectId => {
            assert!(saw_wrong_object, "wrong-object symbol should be rejected")
        }
        SymbolMode::TruncatePayload => {
            assert!(
                saw_symbol_size_mismatch,
                "short symbol should be rejected for size mismatch"
            );
        }
        SymbolMode::OutOfLayoutSbn
        | SymbolMode::RepairEsiOverflow
        | SymbolMode::SourceEsiOutOfRange
        | SymbolMode::ToggleKind => {
            assert!(saw_invalid_metadata, "metadata mutation should be rejected");
        }
        SymbolMode::None | SymbolMode::Duplicate => {}
    }

    if pipeline.is_complete() {
        let decoded = pipeline
            .into_data()
            .expect("complete pipeline should yield decoded object");
        assert_eq!(decoded, payload, "decoded payload drifted from original");
    } else {
        let _ = pipeline.into_data().err();
    }
}

fn build_payload(len: usize, seed: u64) -> Vec<u8> {
    let salt = seed.to_le_bytes();
    let mut payload = Vec::with_capacity(len);
    for idx in 0..len {
        let base = ((idx * 29 + 0x5A) & 0xFF) as u8;
        payload.push(base ^ salt[idx % salt.len()] ^ ((idx >> 3) as u8));
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
    if matches!(mode, SymbolMode::RepairEsiOverflow) {
        base.max(1)
    } else {
        base
    }
}

fn make_pipeline(symbol_size: u16, max_block_size: usize) -> DecodingPipeline {
    DecodingPipeline::new(DecodingConfig {
        symbol_size,
        max_block_size,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: 8192,
        block_timeout: std::time::Duration::from_secs(30),
        verify_auth: false,
    })
}

fn mutate_params(params: ObjectParams, mode: ParamMode) -> ObjectParams {
    match mode {
        ParamMode::Exact => params,
        ParamMode::WrongBlockCount => ObjectParams::new(
            params.object_id,
            params.object_size,
            params.symbol_size,
            params.source_blocks.saturating_add(1),
            params.symbols_per_block,
        ),
        ParamMode::WrongSymbolsPerBlock => ObjectParams::new(
            params.object_id,
            params.object_size,
            params.symbol_size,
            params.source_blocks,
            params.symbols_per_block.saturating_add(1),
        ),
        ParamMode::WrongSymbolSize => ObjectParams::new(
            params.object_id,
            params.object_size,
            params.symbol_size.saturating_add(1),
            params.source_blocks,
            params.symbols_per_block,
        ),
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
    mode: SymbolMode,
    target_index: u16,
    params: ObjectParams,
) {
    if symbols.is_empty() {
        return;
    }

    let idx = usize::from(target_index) % symbols.len();
    let target = symbols[idx].clone();
    let mut replacement = target.clone();

    match mode {
        SymbolMode::None => {}
        SymbolMode::Duplicate => symbols.push(target),
        SymbolMode::OutOfLayoutSbn => {
            replacement = Symbol::new(
                SymbolId::new(target.object_id(), params.source_blocks as u8, target.esi()),
                target.data().to_vec(),
                target.kind(),
            );
            symbols[idx] = replacement;
        }
        SymbolMode::RepairEsiOverflow => {
            replacement = Symbol::new(
                SymbolId::new(target.object_id(), target.sbn(), u32::MAX),
                target.data().to_vec(),
                SymbolKind::Repair,
            );
            symbols[idx] = replacement;
        }
        SymbolMode::SourceEsiOutOfRange => {
            replacement = Symbol::new(
                SymbolId::new(
                    target.object_id(),
                    target.sbn(),
                    u32::from(params.symbols_per_block),
                ),
                target.data().to_vec(),
                SymbolKind::Source,
            );
            symbols[idx] = replacement;
        }
        SymbolMode::WrongObjectId => {
            replacement = Symbol::new(
                SymbolId::new(
                    ObjectId::new_for_test(target.object_id().low().wrapping_add(1)),
                    target.sbn(),
                    target.esi(),
                ),
                target.data().to_vec(),
                target.kind(),
            );
            symbols[idx] = replacement;
        }
        SymbolMode::TruncatePayload => {
            let keep = target.len().saturating_sub(1);
            replacement = Symbol::new(target.id(), target.data()[..keep].to_vec(), target.kind());
            symbols[idx] = replacement;
        }
        SymbolMode::ToggleKind => {
            let toggled = match target.kind() {
                SymbolKind::Source => SymbolKind::Repair,
                SymbolKind::Repair => SymbolKind::Source,
            };
            replacement = Symbol::new(target.id(), target.data().to_vec(), toggled);
            symbols[idx] = replacement;
        }
    }
}
