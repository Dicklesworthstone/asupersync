//! Structure-aware fuzzer for the active proof verifier in `src/raptorq/proof.rs`.
//!
//! The current live verifier seam is `DecodeProof::replay_and_verify`; there is
//! no standalone Merkle-path verifier in this tree. This target maps arbitrary
//! leaf/path byte blobs onto deterministic proof and symbol mutations, then
//! asserts that verification is deterministic and that malformed proofs are
//! rejected instead of accepted or panicking.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::proof::ProofOutcome;
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_K: usize = 24;
const MAX_SYMBOL_SIZE: usize = 128;
const MAX_PAYLOAD_BYTES: usize = MAX_K * MAX_SYMBOL_SIZE;
const MAX_LEAF_BYTES: usize = 128;
const MAX_PATH_NODES: usize = 12;

#[derive(Arbitrary, Clone, Copy, Debug, PartialEq, Eq)]
enum MutationMode {
    None,
    ProofConfig,
    ReceivedSummary,
    OutcomeBinding,
    TraceMetadata,
    SymbolPayload,
    SymbolEquation,
}

#[derive(Arbitrary, Debug)]
struct ProofVerifierSpec {
    k_raw: u8,
    symbol_size_raw: u8,
    seed: u64,
    object_low: u64,
    sbn: u8,
    payload: Vec<u8>,
    leaf: Vec<u8>,
    path: Vec<[u8; 32]>,
    mode: MutationMode,
}

fuzz_target!(|spec: ProofVerifierSpec| {
    let k = 2 + (usize::from(spec.k_raw) % (MAX_K - 1));
    let symbol_size = 1 + (usize::from(spec.symbol_size_raw) % MAX_SYMBOL_SIZE);
    let payload = &spec.payload[..spec.payload.len().min(MAX_PAYLOAD_BYTES)];
    let leaf = &spec.leaf[..spec.leaf.len().min(MAX_LEAF_BYTES)];
    let path = &spec.path[..spec.path.len().min(MAX_PATH_NODES)];
    let object_id = ObjectId::new_for_test(spec.object_low);

    let decoder = InactivationDecoder::new(k, symbol_size, spec.seed);
    let source = build_source_block(payload, k, symbol_size, spec.seed, 0);
    let received = build_received(&decoder, &source, symbol_size, spec.seed);
    let decode = decoder
        .decode_with_proof(&received, object_id, spec.sbn)
        .expect("complete structured input should decode");
    assert!(
        decode.proof.replay_and_verify(&received).is_ok(),
        "baseline proof must verify against its original received set"
    );

    let mut proof = decode.proof.clone();
    let mut mutated_symbols = received.clone();
    let malformed = apply_mutation(&mut proof, &mut mutated_symbols, leaf, path, spec.mode);

    let first = catch_unwind(AssertUnwindSafe(|| {
        proof.replay_and_verify(&mutated_symbols)
    }));
    let second = catch_unwind(AssertUnwindSafe(|| {
        proof.replay_and_verify(&mutated_symbols)
    }));

    assert!(first.is_ok(), "verification panicked on first execution");
    assert!(second.is_ok(), "verification panicked on second execution");

    let first = normalize_verification(first.expect("panic already checked"));
    let second = normalize_verification(second.expect("panic already checked"));
    assert_eq!(first, second, "verification must be deterministic");

    if malformed {
        assert!(first.is_err(), "malformed proof must be rejected");
    } else {
        assert!(first.is_ok(), "baseline proof must verify successfully");
    }
});

fn normalize_verification(result: Result<(), impl ToString>) -> Result<(), String> {
    result.map_err(|err| err.to_string())
}

fn apply_mutation(
    proof: &mut asupersync::raptorq::proof::DecodeProof,
    symbols: &mut [ReceivedSymbol],
    leaf: &[u8],
    path: &[[u8; 32]],
    mode: MutationMode,
) -> bool {
    match mode {
        MutationMode::None => false,
        MutationMode::ProofConfig => {
            proof.config.seed ^= nonzero_u64(leaf, 0x9E37_79B9_7F4A_7C15);
            true
        }
        MutationMode::ReceivedSummary => {
            proof.received.esi_multiset_hash ^= nonzero_u64_from_path(path, 0xA5A5_A5A5_A5A5_A5A5);
            true
        }
        MutationMode::OutcomeBinding => {
            if let ProofOutcome::Success {
                symbols_recovered,
                source_payload_hash,
            } = &mut proof.outcome
            {
                *symbols_recovered = symbols_recovered.saturating_add(1);
                *source_payload_hash ^= nonzero_u64(leaf, 0xD3C4_B2E1_5A5A_A5A5);
            }
            true
        }
        MutationMode::TraceMetadata => {
            proof.elimination.row_ops = proof
                .elimination
                .row_ops
                .saturating_add(1 + usize::from(path_first_byte(path)));
            true
        }
        MutationMode::SymbolPayload => {
            if let Some(symbol) = symbols.get_mut(symbol_index(symbols.len(), leaf, path)) {
                if !symbol.data.is_empty() {
                    let byte_index = byte_index(symbol.data.len(), leaf, path);
                    symbol.data[byte_index] ^= nonzero_byte(leaf, path, 0x5A);
                    return true;
                }
            }
            false
        }
        MutationMode::SymbolEquation => {
            if let Some(symbol) = symbols.get_mut(symbol_index(symbols.len(), leaf, path)) {
                symbol.is_source = true;
                if symbol.columns.is_empty() {
                    symbol.columns.push(proof.config.l);
                } else {
                    symbol.columns[0] = proof.config.l;
                }
                if symbol.coefficients.is_empty() {
                    symbol
                        .coefficients
                        .push(asupersync::raptorq::gf256::Gf256::ONE);
                }
                return true;
            }
            false
        }
    }
}

fn path_first_byte(path: &[[u8; 32]]) -> u8 {
    path.first().map(|node| node[0]).unwrap_or(0)
}

fn nonzero_byte(leaf: &[u8], path: &[[u8; 32]], fallback: u8) -> u8 {
    leaf.iter()
        .copied()
        .chain(path.iter().flat_map(|node| node.iter().copied()))
        .find(|byte| *byte != 0)
        .unwrap_or(fallback)
}

fn nonzero_u64(bytes: &[u8], fallback: u64) -> u64 {
    let mut mixed = 0_u64;
    for (idx, byte) in bytes.iter().copied().enumerate() {
        mixed ^= u64::from(byte) << ((idx % 8) * 8);
        mixed = mixed.rotate_left(7) ^ 0x9E37_79B9_7F4A_7C15;
    }
    if mixed == 0 { fallback } else { mixed }
}

fn nonzero_u64_from_path(path: &[[u8; 32]], fallback: u64) -> u64 {
    let mut mixed = 0_u64;
    for node in path {
        for chunk in node.chunks(8) {
            let mut word = [0_u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            mixed ^= u64::from_le_bytes(word).rotate_left(11);
            mixed = mixed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }
    if mixed == 0 { fallback } else { mixed }
}

fn symbol_index(len: usize, leaf: &[u8], path: &[[u8; 32]]) -> usize {
    let seed = usize::from(nonzero_byte(leaf, path, 1));
    if len == 0 { 0 } else { seed % len }
}

fn byte_index(len: usize, leaf: &[u8], path: &[[u8; 32]]) -> usize {
    let seed = usize::from(nonzero_byte(leaf, path, 7));
    if len == 0 { 0 } else { seed % len }
}

fn build_source_block(
    raw: &[u8],
    k: usize,
    symbol_size: usize,
    seed: u64,
    salt: u64,
) -> Vec<Vec<u8>> {
    let seed_bytes = seed.to_le_bytes();
    let salt_bytes = salt.to_le_bytes();
    let mut source = Vec::with_capacity(k);
    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let base = if raw.is_empty() {
                ((row * 29 + col * 17 + 0x5A) & 0xFF) as u8
            } else {
                raw[(row * symbol_size + col) % raw.len()]
            };
            let mixed = base
                ^ seed_bytes[(row + col) % seed_bytes.len()]
                ^ salt_bytes[(row * 3 + col) % salt_bytes.len()]
                ^ ((row * 31 + col * 7) as u8);
            symbol.push(mixed);
        }
        source.push(symbol);
    }
    source
}

fn build_received(
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    symbol_size: usize,
    seed: u64,
) -> Vec<ReceivedSymbol> {
    let encoder = SystematicEncoder::new(source, symbol_size, seed).expect("normalized encoder");
    let mut received = decoder.constraint_symbols();
    for (index, data) in source.iter().enumerate() {
        received.push(ReceivedSymbol::source(index as u32, data.clone()));
    }
    for esi in (source.len() as u32)..(decoder.params().l as u32) {
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
