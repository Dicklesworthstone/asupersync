//! Manual RaptorQ profiling for post-SIMD bottleneck analysis.

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::rfc6330::rand as rfc_rand;
use asupersync::raptorq::systematic::SystematicEncoder;
use std::collections::BTreeSet;
use std::time::Instant;

const ITERATIONS: usize = 5;
const K: usize = 2048;
const SYMBOL_SIZE: usize = 16;
const LOSS_PERMILLE: usize = 8;
const REPAIR_OVERHEAD: usize = 8;
const SEED: u64 = 0x6330_2048_0000_0001;
const DROP_SEED: u32 = 0xA1B2_C248;

fn main() {
    println!("Manual RaptorQ profiling");

    for iteration in 0..ITERATIONS {
        println!(
            "Iteration {iteration}: running K={K}, symbol_size={SYMBOL_SIZE}, loss={} permille",
            LOSS_PERMILLE
        );

        let start = Instant::now();
        let result = run_raptorq_decode_workload(iteration, K, SYMBOL_SIZE, LOSS_PERMILLE);
        let elapsed = start.elapsed();

        println!(
            "Iteration {iteration}: decoded {} bytes from {} received symbols ({} repairs, {} dropped) in {:.1}ms; dense_core={}x{}, gauss_ops={}",
            result.decoded_bytes,
            result.received_symbols,
            result.repair_symbols,
            result.dropped_sources,
            elapsed.as_secs_f64() * 1000.0,
            result.dense_core_rows,
            result.dense_core_cols,
            result.gauss_ops
        );
    }

    println!("Profiling workload completed");
}

#[derive(Debug, Clone, Copy)]
struct ProfileResult {
    decoded_bytes: usize,
    received_symbols: usize,
    repair_symbols: usize,
    dropped_sources: usize,
    dense_core_rows: usize,
    dense_core_cols: usize,
    gauss_ops: usize,
}

fn run_raptorq_decode_workload(
    iteration: usize,
    k: usize,
    symbol_size: usize,
    loss_permille: usize,
) -> ProfileResult {
    let source = make_source_data(k, symbol_size, iteration);
    let drop_indices = pick_drop_indices(k, loss_permille, iteration);
    let repair_count = drop_indices.len() + REPAIR_OVERHEAD;
    let seed = SEED.wrapping_add(iteration as u64);

    let encoder =
        SystematicEncoder::new(&source, symbol_size, seed).expect("profile encoder setup failed");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_received_symbols(&decoder, &encoder, &source, &drop_indices, repair_count);

    let decoded = decoder.decode(&received).unwrap_or_else(|err| {
        panic!(
            "real RaptorQ profile workload failed at iteration {iteration} with {repair_count} repairs: {err:?}"
        )
    });
    assert_eq!(
        decoded.source, source,
        "profile workload must recover the original source symbols"
    );

    ProfileResult {
        decoded_bytes: decoded.source.iter().map(Vec::len).sum(),
        received_symbols: received.len(),
        repair_symbols: repair_count,
        dropped_sources: drop_indices.len(),
        dense_core_rows: decoded.stats.dense_core_rows,
        dense_core_cols: decoded.stats.dense_core_cols,
        gauss_ops: decoded.stats.gauss_ops,
    }
}

fn make_source_data(k: usize, symbol_size: usize, iteration: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|symbol_idx| {
            (0..symbol_size)
                .map(|byte_idx| {
                    ((symbol_idx.wrapping_mul(73)
                        + byte_idx.wrapping_mul(29)
                        + iteration.wrapping_mul(17)
                        + 11)
                        % 256) as u8
                })
                .collect()
        })
        .collect()
}

fn pick_drop_indices(k: usize, loss_permille: usize, iteration: usize) -> Vec<usize> {
    assert!(k > 0, "profile workload needs at least one source symbol");
    let max_drops = (k / 4).max(1);
    let target = k
        .saturating_mul(loss_permille)
        .div_ceil(1000)
        .clamp(1, max_drops);
    let limit = u32::try_from(k).expect("profile K must fit in u32");
    let mut drops = BTreeSet::new();
    let mut draw = u32::try_from(iteration).expect("iteration index must fit in u32");

    while drops.len() < target {
        let idx = usize::try_from(rfc_rand(
            DROP_SEED.wrapping_add(draw),
            (drops.len() % 251) as u8,
            limit,
        ))
        .expect("drop draw must fit in usize");
        drops.insert(idx);
        draw = draw.wrapping_add(1);
    }

    drops.into_iter().collect()
}

fn build_received_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    drop_indices: &[usize],
    repair_count: usize,
) -> Vec<ReceivedSymbol> {
    let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();
    let mut received = decoder.constraint_symbols();

    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(
                u32::try_from(esi).expect("source ESI must fit in u32"),
                data.clone(),
            ));
        }
    }

    let k_u32 = u32::try_from(source.len()).expect("profile K must fit in u32");
    for repair_offset in 0..repair_count {
        let esi = k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
        let (cols, coefs) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"));
        received.push(ReceivedSymbol::repair(
            esi,
            cols,
            coefs,
            encoder.repair_symbol(esi),
        ));
    }

    received
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_profile_workload_recovers_original_source() {
        let result = run_raptorq_decode_workload(0, 32, 8, 125);

        assert_eq!(result.decoded_bytes, 256);
        assert_eq!(result.dropped_sources, 4);
        assert_eq!(result.repair_symbols, 12);
        assert!(
            result.received_symbols >= 40,
            "constraints plus source and repair symbols must feed the real decoder"
        );
    }

    #[test]
    fn source_no_longer_contains_decoder_shortcut() {
        let source = include_str!("raptorq_profile_manual.rs");
        assert!(!source.contains(concat!("simulate_", "raptorq_decode_work")));
        assert!(!source.contains(&["without depending on ", "the complex encoder"].concat()));
    }
}
