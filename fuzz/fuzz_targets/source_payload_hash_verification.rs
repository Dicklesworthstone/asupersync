//! Fuzz target for RaptorQ DecodeProof source-payload-hash replay verification.
//!
//! This harness targets `src/raptorq/proof.rs` via the public
//! `DecodeProof::replay_and_verify` API.
//!
//! Coverage goals:
//! - matching replay inputs continue to verify successfully
//! - payload-divergent source blocks with identical symbol structure are rejected
//!   specifically through the `source_payload_hash` outcome binding
//! - regenerated repair symbols for mutated sources do not trigger panics

#![no_main]

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;

const MAX_K: usize = 24;
const MAX_SYMBOL_SIZE: usize = 128;
const MAX_PAYLOAD_BYTES: usize = MAX_K * MAX_SYMBOL_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MutationMode {
    Identical,
    SaltShift,
    FlipByte,
    RotateRows,
}

#[derive(Clone, Copy, Debug)]
struct MutationPlan {
    mode: MutationMode,
    symbol_index: usize,
    byte_index: usize,
    rotate_by: usize,
    flip_mask: u8,
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    let k = 2 + (usize::from(data[0]) % (MAX_K - 1));
    let symbol_size = 1 + (usize::from(data[1]) % MAX_SYMBOL_SIZE);
    let seed = read_u64(data, 2);
    let object_id = ObjectId::new_for_test(read_u64(data, 10));
    let sbn = data[18];
    let plan = MutationPlan {
        mode: match data[19] % 4 {
            0 => MutationMode::Identical,
            1 => MutationMode::SaltShift,
            2 => MutationMode::FlipByte,
            _ => MutationMode::RotateRows,
        },
        symbol_index: usize::from(data[20]) % k,
        byte_index: usize::from(data[21]) % symbol_size,
        rotate_by: 1 + (usize::from(data[22]) % (k - 1)),
        flip_mask: if data[23] == 0 { 1 } else { data[23] },
    };
    let payload = &data[24..data.len().min(24 + MAX_PAYLOAD_BYTES)];

    let original_source = build_source_block(payload, k, symbol_size, seed, 0);
    let mutated_source = mutate_source(&original_source, payload, seed, plan);

    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let original_received = build_received(&decoder, &original_source, symbol_size, seed);
    let original_result = decoder
        .decode_with_proof(&original_received, object_id, sbn)
        .expect("complete structured input should decode");
    assert_eq!(original_result.result.source, original_source);
    assert!(
        original_result.proof.replay_and_verify(&original_received).is_ok(),
        "proof must verify against its original received set"
    );

    let mutated_received = build_received(&decoder, &mutated_source, symbol_size, seed);
    let mutated_result = decoder
        .decode_with_proof(&mutated_received, object_id, sbn)
        .expect("mutated structured input should still decode");
    assert_eq!(mutated_result.result.source, mutated_source);

    if mutated_source == original_source {
        assert!(
            original_result.proof.replay_and_verify(&mutated_received).is_ok(),
            "identical replay inputs must continue to verify"
        );
    } else {
        let err = original_result
            .proof
            .replay_and_verify(&mutated_received)
            .expect_err("payload-divergent replay must fail verification");
        assert!(
            err.to_string().contains("source_payload_hash"),
            "expected source_payload_hash mismatch, got {err}"
        );
        assert!(
            mutated_result.proof.replay_and_verify(&mutated_received).is_ok(),
            "proof must verify against its own regenerated payload"
        );
    }
});

fn read_u64(data: &[u8], start: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (offset, slot) in bytes.iter_mut().enumerate() {
        *slot = data.get(start + offset).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
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

fn mutate_source(
    original: &[Vec<u8>],
    raw: &[u8],
    seed: u64,
    plan: MutationPlan,
) -> Vec<Vec<u8>> {
    let mut mutated = original.to_vec();
    match plan.mode {
        MutationMode::Identical => {}
        MutationMode::SaltShift => {
            mutated = build_source_block(
                raw,
                original.len(),
                original[0].len(),
                seed,
                seed.rotate_left(13) ^ 0xA5A5_5A5A_D3C4_B2E1,
            );
        }
        MutationMode::FlipByte => {
            mutated[plan.symbol_index][plan.byte_index] ^= plan.flip_mask;
        }
        MutationMode::RotateRows => {
            mutated.rotate_left(plan.rotate_by);
        }
    }

    if plan.mode != MutationMode::Identical && mutated == original {
        mutated[plan.symbol_index][plan.byte_index] ^= plan.flip_mask;
    }

    mutated
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
        let (cols, coefs) = decoder.repair_equation(esi);
        received.push(ReceivedSymbol::repair(
            esi,
            cols,
            coefs,
            encoder.repair_symbol(esi),
        ));
    }
    received
}
