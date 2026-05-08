//! Structure-aware overhead fuzzer for RaptorQ decode with surplus repair.
//!
//! The target removes at least one systematic source symbol, finds the first
//! repair-symbol prefix that makes the block decodable, then feeds that prefix
//! plus exactly 2x additional repair symbols through the streaming pipeline.
//! The oracle asserts that decode completes at the first required prefix and
//! that later repairs are rejected as already decoded, not counted as consumed.
//! It also permutes the required repair prefix and feeds duplicate repair
//! symbols after completion so decoder progress is independent of arrival order
//! and duplicate post-completion symbols are not counted as new input.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::config::EncodingConfig;
use asupersync::decoding::{DecodingConfig, DecodingPipeline, RejectReason, SymbolAcceptResult};
use asupersync::encoding::EncodingPipeline;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::security::{AuthenticatedSymbol, AuthenticationTag};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, ObjectParams, Symbol, SymbolKind};
use libfuzzer_sys::fuzz_target;

const K_CANDIDATES: &[usize] = &[4, 8, 10, 12];
const SYMBOL_SIZE_CANDIDATES: &[usize] = &[4, 8, 16];
const REPAIR_SEARCH_MULTIPLIER: usize = 4;
const EXTRA_REPAIR_MULTIPLIER: usize = 2;
const MAX_SOURCE_BYTES: usize = 12 * 16;
const MAX_DUPLICATE_REPAIRS: usize = 8;
const MAX_REPAIR_PREFIX_SEARCH: usize = 12;

#[derive(Debug, Arbitrary)]
struct ExtraRepairInput {
    k_selector: u8,
    symbol_size_selector: u8,
    object_seed: u64,
    repair_order_seed: u64,
    missing_count: u8,
    missing_selectors: Vec<u16>,
    duplicate_repair_count: u8,
    duplicate_selectors: Vec<u16>,
    source_bytes: Vec<u8>,
}

impl ExtraRepairInput {
    fn normalize(&mut self) {
        self.source_bytes.truncate(MAX_SOURCE_BYTES);
        self.missing_selectors.truncate(64);
        self.duplicate_selectors.truncate(MAX_DUPLICATE_REPAIRS);
    }
}

fuzz_target!(|input: ExtraRepairInput| {
    let mut input = input;
    input.normalize();
    exercise_extra_repair_decode(&input);
});

fn exercise_extra_repair_decode(input: &ExtraRepairInput) {
    let k = select_k(input.k_selector);
    let symbol_size = select_symbol_size(input.symbol_size_selector);
    let object_id = ObjectId::new_for_test(input.object_seed);
    let object_size = k * symbol_size;
    let source = deterministic_source(&input.source_bytes, object_size, input.object_seed);
    let repair_budget = k * REPAIR_SEARCH_MULTIPLIER;

    let encoded = encode_symbols(object_id, &source, symbol_size, repair_budget);
    let (sources, repairs) = split_symbols(encoded);
    assert_eq!(
        sources.len(),
        k,
        "encoder must emit exactly K source symbols"
    );
    assert_eq!(
        repairs.len(),
        repair_budget,
        "encoder must emit the requested repair search budget"
    );

    let missing = missing_source_indices(input, k);
    let kept_sources = keep_sources(&sources, &missing);
    let decoder = InactivationDecoder::new(k, symbol_size, seed_for_block(object_id, 0));
    let Some(required_repairs) = first_decodable_repair_prefix(&decoder, &kept_sources, &repairs)
    else {
        return;
    };
    assert!(
        required_repairs > 0,
        "dropping at least one source should require at least one repair"
    );

    let repairs_to_offer = required_repairs * (EXTRA_REPAIR_MULTIPLIER + 1);
    if repairs_to_offer > repairs.len() {
        return;
    }

    let required_repair_prefix = permute_repairs(&repairs[..required_repairs], input);
    assert_eq!(
        sorted_esis(&required_repair_prefix),
        sorted_esis(&repairs[..required_repairs]),
        "repair-prefix permutation must preserve the selected ESI set"
    );
    let duplicate_repairs = duplicate_repairs_after_completion(&required_repair_prefix, input);
    let extra_repairs = &repairs[required_repairs..repairs_to_offer];

    let mut stream =
        Vec::with_capacity(kept_sources.len() + repairs_to_offer + duplicate_repairs.len());
    stream.extend(kept_sources.iter().cloned());
    stream.extend(required_repair_prefix.iter().cloned());
    stream.extend(duplicate_repairs.iter().cloned());
    stream.extend(extra_repairs.iter().cloned());

    let consumed = feed_until_complete(object_id, object_size, symbol_size, k, &source, &stream)
        .expect("streaming decoder must complete with permuted surplus repair overhead");
    let expected_consumed = kept_sources.len() + required_repairs;
    assert!(
        consumed <= expected_consumed,
        "decoder should complete no later than the selected required source+repair prefix"
    );
    assert_eq!(
        stream.len() - consumed,
        (expected_consumed - consumed)
            + duplicate_repairs.len()
            + required_repairs * EXTRA_REPAIR_MULTIPLIER,
        "stream must leave only post-completion required, duplicate, and 2x repair symbols unconsumed"
    );
}

fn select_k(selector: u8) -> usize {
    K_CANDIDATES[usize::from(selector) % K_CANDIDATES.len()]
}

fn select_symbol_size(selector: u8) -> usize {
    SYMBOL_SIZE_CANDIDATES[usize::from(selector) % SYMBOL_SIZE_CANDIDATES.len()]
}

fn deterministic_source(raw: &[u8], len: usize, seed: u64) -> Vec<u8> {
    let salt = seed.to_le_bytes();
    (0..len)
        .map(|idx| {
            let fallback = (idx as u8).wrapping_mul(31)
                ^ salt[idx % salt.len()]
                ^ ((idx / salt.len()) as u8).wrapping_mul(17);
            raw.get(idx % raw.len().max(1)).copied().unwrap_or(fallback) ^ fallback
        })
        .collect()
}

fn encode_symbols(
    object_id: ObjectId,
    source: &[u8],
    symbol_size: usize,
    repair_budget: usize,
) -> Vec<Symbol> {
    let symbol_size = u16::try_from(symbol_size).expect("bounded symbol size fits u16");
    let config = EncodingConfig {
        symbol_size,
        max_block_size: source.len(),
        repair_overhead: 1.0,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    };
    let pool = SymbolPool::new(PoolConfig {
        symbol_size,
        initial_size: 0,
        max_size: 0,
        allow_growth: false,
        growth_increment: 0,
    });
    let mut pipeline = EncodingPipeline::new(config, pool);

    pipeline
        .encode_with_repair(object_id, source, repair_budget)
        .collect::<Result<Vec<_>, _>>()
        .expect("bounded one-block source must be encodable")
        .into_iter()
        .map(|encoded| encoded.into_symbol())
        .collect()
}

fn split_symbols(symbols: Vec<Symbol>) -> (Vec<Symbol>, Vec<Symbol>) {
    symbols
        .into_iter()
        .partition(|symbol| symbol.kind() == SymbolKind::Source)
}

fn missing_source_indices(input: &ExtraRepairInput, k: usize) -> Vec<usize> {
    let max_missing = 1;
    let target = (usize::from(input.missing_count) % max_missing) + 1;
    let mut missing = Vec::with_capacity(target);
    let mut used = vec![false; k];
    let stride = (((input.object_seed.rotate_left(17) as usize) | 1) % k).max(1);
    let mut cursor = input.object_seed as usize % k;

    for offset in 0..target {
        let selector = input
            .missing_selectors
            .get(offset)
            .copied()
            .unwrap_or_else(|| input.object_seed.wrapping_add(offset as u64) as u16);
        let mut candidate = (cursor + usize::from(selector)) % k;
        while used[candidate] {
            candidate = (candidate + stride) % k;
        }
        used[candidate] = true;
        missing.push(candidate);
        cursor = (candidate + stride) % k;
    }

    missing.sort_unstable();
    missing
}

fn keep_sources(sources: &[Symbol], missing: &[usize]) -> Vec<Symbol> {
    let mut is_missing = vec![false; sources.len()];
    for &index in missing {
        is_missing[index] = true;
    }

    sources
        .iter()
        .filter(|symbol| !is_missing[symbol.esi() as usize])
        .cloned()
        .collect()
}

fn permute_repairs(repairs: &[Symbol], input: &ExtraRepairInput) -> Vec<Symbol> {
    let mut ordered = repairs.to_vec();
    let mut state = input
        .repair_order_seed
        .wrapping_add(input.object_seed.rotate_left(11))
        | 1;

    for index in (1..ordered.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let swap_with = (state as usize) % (index + 1);
        ordered.swap(index, swap_with);
    }

    ordered
}

fn duplicate_repairs_after_completion(repairs: &[Symbol], input: &ExtraRepairInput) -> Vec<Symbol> {
    let max_duplicates = repairs.len().min(MAX_DUPLICATE_REPAIRS);
    if max_duplicates == 0 {
        return Vec::new();
    }

    let target = usize::from(input.duplicate_repair_count) % max_duplicates + 1;
    (0..target)
        .map(|offset| {
            let selector = input
                .duplicate_selectors
                .get(offset)
                .copied()
                .unwrap_or_else(|| input.object_seed.wrapping_add(offset as u64) as u16);
            repairs[usize::from(selector) % repairs.len()].clone()
        })
        .collect()
}

fn sorted_esis(symbols: &[Symbol]) -> Vec<u32> {
    let mut esis = symbols.iter().map(Symbol::esi).collect::<Vec<_>>();
    esis.sort_unstable();
    esis
}

fn first_decodable_repair_prefix(
    decoder: &InactivationDecoder,
    kept_sources: &[Symbol],
    repairs: &[Symbol],
) -> Option<usize> {
    for repair_count in 1..=repairs.len().min(MAX_REPAIR_PREFIX_SEARCH) {
        let mut received = decoder.constraint_symbols();
        extend_received_symbols(decoder, &mut received, kept_sources)?;
        extend_received_symbols(decoder, &mut received, &repairs[..repair_count])?;
        if decoder.decode(&received).is_ok() {
            return Some(repair_count);
        }
    }

    None
}

fn extend_received_symbols(
    decoder: &InactivationDecoder,
    received: &mut Vec<ReceivedSymbol>,
    symbols: &[Symbol],
) -> Option<()> {
    for symbol in symbols {
        match symbol.kind() {
            SymbolKind::Source => {
                received.push(ReceivedSymbol::source(symbol.esi(), symbol.data().to_vec()));
            }
            SymbolKind::Repair => {
                let (columns, coefficients) = decoder.repair_equation(symbol.esi()).ok()?;
                received.push(ReceivedSymbol::repair(
                    symbol.esi(),
                    columns,
                    coefficients,
                    symbol.data().to_vec(),
                ));
            }
        }
    }

    Some(())
}

fn feed_until_complete(
    object_id: ObjectId,
    object_size: usize,
    symbol_size: usize,
    k: usize,
    expected_source: &[u8],
    stream: &[Symbol],
) -> Option<usize> {
    let mut decoder = DecodingPipeline::new(DecodingConfig {
        symbol_size: u16::try_from(symbol_size).expect("bounded symbol size fits u16"),
        max_block_size: object_size,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: stream.len() + 1,
        verify_auth: false,
        ..Default::default()
    });
    decoder
        .set_object_params(ObjectParams::new(
            object_id,
            object_size as u64,
            u16::try_from(symbol_size).expect("bounded symbol size fits u16"),
            1,
            u16::try_from(k).expect("bounded K fits u16"),
        ))
        .expect("bounded object params must be valid");

    let mut completed_at = None;
    let mut block_already_decoded = 0usize;

    for (idx, symbol) in stream.iter().cloned().enumerate() {
        let accepted = decoder
            .feed(AuthenticatedSymbol::from_parts(
                symbol,
                AuthenticationTag::zero(),
            ))
            .expect("bounded unauthenticated decode feed must be total");

        match accepted {
            SymbolAcceptResult::BlockComplete { data, .. } => {
                assert!(
                    completed_at.is_none(),
                    "decoder must complete a one-block stream exactly once"
                );
                assert_eq!(
                    data.len(),
                    object_size,
                    "decoded block must be truncated to original object size"
                );
                assert_eq!(
                    data, expected_source,
                    "decoded block bytes must match the original source"
                );
                completed_at = Some(idx + 1);
            }
            SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded) => {
                assert!(
                    completed_at.is_some(),
                    "block-already-decoded rejection must only happen after completion"
                );
                block_already_decoded += 1;
            }
            SymbolAcceptResult::Duplicate => {
                panic!("extra-repair stream must not contain duplicate symbols");
            }
            SymbolAcceptResult::Rejected(
                RejectReason::InsufficientRank | RejectReason::InconsistentEquations,
            ) if completed_at.is_none() => {}
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. }
                if completed_at.is_none() => {}
            other => {
                panic!("unexpected decode feed result for extra-repair stream: {other:?}");
            }
        }
    }

    let consumed = completed_at?;
    assert_eq!(
        block_already_decoded,
        stream.len() - consumed,
        "every symbol after completion must be rejected instead of consumed"
    );
    assert_eq!(
        decoder.progress().symbols_received,
        consumed,
        "decoder progress must count only symbols accepted before completion"
    );

    Some(consumed)
}

fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
    let obj = object_id.as_u128();
    let hi = (obj >> 64) as u64;
    let lo = obj as u64;
    let mut seed = hi ^ lo.rotate_left(13);
    seed ^= u64::from(sbn) << 56;
    if seed == 0 { 1 } else { seed }
}
