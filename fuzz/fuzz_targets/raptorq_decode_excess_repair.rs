//! Structure-aware fuzz target for RaptorQ decode with surplus repair symbols.
//!
//! Builds a one-block object with some systematic source symbols missing, then
//! offers the receiver 2*K repair symbols. The oracle first finds the smallest
//! repair prefix that makes the block decodable, then asserts the streaming
//! decoder completes at that prefix and rejects every later repair symbol.

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

const K_CANDIDATES: &[usize] = &[4, 8, 10, 12, 16, 24, 32, 42, 64];
const SYMBOL_SIZE_CANDIDATES: &[usize] = &[4, 8, 16, 24, 32, 48, 64];
const REPAIR_MULTIPLIER: usize = 2;
const MAX_SOURCE_BYTES: usize = 64 * 64;

#[derive(Debug, Arbitrary)]
struct ExcessRepairInput {
    k_selector: u8,
    symbol_size_selector: u8,
    object_seed: u64,
    missing_count: u8,
    missing_selectors: Vec<u16>,
    source_bytes: Vec<u8>,
}

impl ExcessRepairInput {
    fn normalize(&mut self) {
        self.source_bytes.truncate(MAX_SOURCE_BYTES);
        self.missing_selectors.truncate(64);
    }
}

fuzz_target!(|input: ExcessRepairInput| {
    let mut input = input;
    input.normalize();
    exercise_excess_repair_decode(&input);
});

fn exercise_excess_repair_decode(input: &ExcessRepairInput) {
    let k = select_k(input.k_selector);
    let symbol_size = select_symbol_size(input.symbol_size_selector);
    let object_id = ObjectId::new_for_test(input.object_seed);
    let object_size = k * symbol_size;
    let source = deterministic_source(&input.source_bytes, object_size, input.object_seed);
    let repair_budget = k * REPAIR_MULTIPLIER;

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
        "encoder must emit the requested 2*K repair symbols"
    );

    let missing = missing_source_indices(input, k);
    let kept_sources = keep_sources(&sources, &missing);
    assert!(
        repair_budget >= missing.len().saturating_mul(4),
        "2*K repair budget must be far larger than the K-K_e replacement need"
    );

    let seed = seed_for_block(object_id, 0);
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let required_repairs = first_decodable_repair_prefix(&decoder, &kept_sources, &repairs)
        .expect("2*K repair symbols should contain a decodable prefix");
    assert!(
        required_repairs < repair_budget,
        "excess-repair target must leave surplus repairs after the first decodable prefix"
    );

    let mut stream = Vec::with_capacity(kept_sources.len() + repair_budget);
    stream.extend(kept_sources.iter().cloned());
    stream.extend(repairs.iter().cloned());

    let consumed = feed_until_complete(object_id, object_size, symbol_size, k, &stream)
        .expect("streaming decoder must complete with a 2*K repair budget");
    let expected_consumed = kept_sources.len() + required_repairs;
    assert_eq!(
        consumed, expected_consumed,
        "decoder should consume only the first decodable source+repair prefix"
    );
    assert!(
        stream.len() > consumed,
        "2*K repair stream must contain symbols left unread after completion"
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

fn missing_source_indices(input: &ExcessRepairInput, k: usize) -> Vec<usize> {
    let max_missing = (k / 2).max(1);
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

fn first_decodable_repair_prefix(
    decoder: &InactivationDecoder,
    kept_sources: &[Symbol],
    repairs: &[Symbol],
) -> Option<usize> {
    for repair_count in 0..=repairs.len() {
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
                    "decoded block must be truncated to the original object size"
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
                panic!("excess-repair stream must not contain duplicate symbols");
            }
            SymbolAcceptResult::Rejected(
                RejectReason::InsufficientRank | RejectReason::InconsistentEquations,
            ) if completed_at.is_none() => {}
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. }
                if completed_at.is_none() => {}
            other => {
                panic!("unexpected decode feed result for excess-repair stream: {other:?}");
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
