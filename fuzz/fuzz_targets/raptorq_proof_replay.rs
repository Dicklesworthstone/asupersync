//! br-asupersync-wg35z0 — Fuzz `DecodeProof::replay_and_verify` against
//! adversarial `ReceivedSymbol` streams.
//!
//! Invariants asserted:
//!   1. No panic — `replay_and_verify` must return `Result<(), ReplayError>`
//!      on any byte input, including malformed / contradictory symbol streams.
//!   2. No OOM — bounded by `MAX_SYMBOL_BYTES` and `MAX_SYMBOLS` so a single
//!      run cannot allocate beyond the configured caps.
//!   3. No infinite loop — `replay_and_verify` runs the inactivation decoder
//!      to completion or failure on a finite K and a finite-length symbol
//!      stream; libfuzzer's per-iteration timeout would catch any divergence.
//!
//! Input space: arbitrary bytes interpreted as a packed (DecodeConfig,
//! Vec<ReceivedSymbol>) descriptor, with sizes capped to keep individual
//! cases small enough for libFuzzer's default 4-second budget.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::raptorq::decoder::ReceivedSymbol;
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::proof::{DecodeConfig, DecodeProof, ProofOutcome};
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;

const MAX_K: usize = 32;
const MAX_SYMBOL_SIZE: usize = 256;
const MAX_SYMBOLS: usize = 64;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Pull a deterministic config out of the prefix.
    let mut cur = 0usize;
    let read_u8 = |cur: &mut usize, data: &[u8]| -> Option<u8> {
        let b = *data.get(*cur)?;
        *cur += 1;
        Some(b)
    };

    let k_byte = match read_u8(&mut cur, data) {
        Some(b) => b,
        None => return,
    };
    let symbol_size_byte = match read_u8(&mut cur, data) {
        Some(b) => b,
        None => return,
    };
    let n_symbols_byte = match read_u8(&mut cur, data) {
        Some(b) => b,
        None => return,
    };
    let seed_byte = match read_u8(&mut cur, data) {
        Some(b) => b,
        None => return,
    };

    let k = ((k_byte as usize) % MAX_K).max(1);
    let symbol_size = (((symbol_size_byte as usize) % MAX_SYMBOL_SIZE) + 8) & !7; // multiple of 8, >=8
    let n_symbols = ((n_symbols_byte as usize) % MAX_SYMBOLS).max(1);
    let seed = u64::from(seed_byte);

    // Compute S, H, L the way DecodeConfig expects them — pick conservative
    // small values consistent with K. We deliberately seed with potentially
    // wrong values to exercise the proof comparator's mismatch path.
    let s = (k.next_power_of_two().trailing_zeros() as usize).max(1);
    let h = s;
    let l = k + s + h;

    let config = DecodeConfig {
        object_id: ObjectId::new(0, u64::from(seed_byte)),
        sbn: 0,
        k,
        s,
        h,
        l,
        symbol_size,
        seed,
    };

    // Build adversarial ReceivedSymbol stream from remaining bytes.
    let mut symbols = Vec::with_capacity(n_symbols);
    for chunk in data[cur..].chunks(8).take(n_symbols) {
        if chunk.len() < 4 {
            break;
        }
        let esi = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) % (l as u32 * 4);
        let is_source = (chunk[0] & 1) != 0;
        // Columns: pick 1-3 column indices from the remaining bytes mod L.
        let n_cols = ((chunk.get(4).copied().unwrap_or(1) as usize) % 3) + 1;
        let columns: Vec<usize> = (0..n_cols)
            .map(|i| {
                (chunk.get(5 + i).copied().unwrap_or(0) as usize) % l.max(1)
            })
            .collect();
        let coefficients: Vec<Gf256> = columns
            .iter()
            .enumerate()
            .map(|(i, _)| Gf256::new(chunk.get(i % chunk.len()).copied().unwrap_or(1)))
            .collect();
        let mut sym_data = vec![0u8; symbol_size.min(MAX_SYMBOL_SIZE)];
        for (i, b) in sym_data.iter_mut().enumerate() {
            *b = chunk[i % chunk.len()];
        }
        symbols.push(ReceivedSymbol {
            esi,
            is_source,
            columns,
            coefficients,
            data: sym_data,
        });
    }

    // Build a minimal "expected" proof with empty traces and a Failure
    // outcome — this is intentionally non-equal to whatever the actual
    // decoder will produce for the random inputs, so the comparator
    // exercises every divergence-detection path.
    use asupersync::raptorq::proof::{
        EliminationTrace, PeelingTrace, ReceivedSummary,
    };
    let proof = DecodeProof {
        version: 1,
        config,
        received: ReceivedSummary::from_received(
            symbols.iter().map(|s| (s.esi, s.is_source)),
        ),
        peeling: PeelingTrace::default(),
        elimination: EliminationTrace::default(),
        outcome: ProofOutcome::Success {
            symbols_recovered: 0,
            source_payload_hash: 0,
        },
    };

    // Invariant: replay_and_verify never panics on any bytes.
    let result = catch_unwind(AssertUnwindSafe(|| proof.replay_and_verify(&symbols)));
    assert!(
        result.is_ok(),
        "replay_and_verify panicked on adversarial input"
    );
});
