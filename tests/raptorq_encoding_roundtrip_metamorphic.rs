//! Metamorphic roundtrip coverage for the RaptorQ systematic encoder/decoder pair.

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::{EmittedSymbol, SystematicEncoder};
use asupersync::util::DetRng;
use insta::assert_json_snapshot;
use serde::Serialize;

const CANONICAL_SYMBOL_SIZE: usize = 8;
const CANONICAL_REPAIR_COUNT: usize = 4;

#[derive(Serialize)]
struct CanonicalPacketGolden {
    esi: u32,
    kind: &'static str,
    degree: usize,
    data_hex: String,
}

#[derive(Serialize)]
struct CanonicalVectorGolden {
    case_name: String,
    payload_size: usize,
    symbol_size: usize,
    k: usize,
    k_prime: usize,
    repair_count: usize,
    packet_count: usize,
    packets: Vec<CanonicalPacketGolden>,
}

fn make_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(seed);
    (0..k)
        .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
        .collect()
}

fn build_received_symbols(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    dropped_source_indices: &[usize],
    extra_repairs: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let l = decoder.params().l;
    let mut received = decoder.constraint_symbols();

    for (esi, data) in source.iter().enumerate() {
        if !dropped_source_indices.contains(&esi) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }

    let repair_upper = (l + extra_repairs) as u32;
    for esi in (k as u32)..repair_upper {
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"));
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(
            esi,
            columns,
            coefficients,
            repair_data,
        ));
    }

    received
}

fn decode_source_symbols(
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
) -> Vec<Vec<u8>> {
    decoder
        .decode(received)
        .expect("metamorphic roundtrip should decode")
        .source
}

fn flatten_source_symbols(source: &[Vec<u8>], original_len: usize) -> Vec<u8> {
    source
        .iter()
        .flatten()
        .copied()
        .take(original_len)
        .collect()
}

fn permute_symbols(symbols: &mut [ReceivedSymbol], seed: u64) {
    let mut rng = DetRng::new(seed);
    for idx in (1..symbols.len()).rev() {
        let swap_idx = (rng.next_u32() as usize) % (idx + 1);
        symbols.swap(idx, swap_idx);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn deterministic_payload(payload_size: usize, salt: u8) -> Vec<u8> {
    (0..payload_size)
        .map(|idx| salt.wrapping_add((idx as u8).wrapping_mul(37)))
        .collect()
}

fn payload_to_source_symbols(payload: &[u8], symbol_size: usize) -> Vec<Vec<u8>> {
    payload
        .chunks(symbol_size)
        .map(|chunk| {
            let mut symbol = vec![0u8; symbol_size];
            symbol[..chunk.len()].copy_from_slice(chunk);
            symbol
        })
        .collect()
}

fn build_received_from_emitted(
    decoder: &InactivationDecoder,
    emitted: &[EmittedSymbol],
) -> Vec<ReceivedSymbol> {
    let mut received = decoder.constraint_symbols();

    for symbol in emitted {
        if symbol.is_source {
            received.push(ReceivedSymbol::source(symbol.esi, symbol.data.clone()));
        } else {
            let (columns, coefficients) =
                decoder.repair_equation(symbol.esi).unwrap_or_else(|err| {
                    panic!("repair equation for esi={} failed: {err:?}", symbol.esi)
                });
            received.push(ReceivedSymbol::repair(
                symbol.esi,
                columns,
                coefficients,
                symbol.data.clone(),
            ));
        }
    }

    received
}

fn canonical_roundtrip_case(
    case_name: &str,
    payload_size: usize,
    expected_k: usize,
    seed: u64,
) -> CanonicalVectorGolden {
    let payload = deterministic_payload(payload_size, seed as u8);
    let source = payload_to_source_symbols(&payload, CANONICAL_SYMBOL_SIZE);
    assert_eq!(
        source.len(),
        expected_k,
        "{case_name} fixture drifted away from its expected source-symbol count"
    );

    let mut encoder =
        SystematicEncoder::new(&source, CANONICAL_SYMBOL_SIZE, seed).expect("encoder");
    let emitted = encoder.emit_all(CANONICAL_REPAIR_COUNT);
    let decoder = InactivationDecoder::new(expected_k, CANONICAL_SYMBOL_SIZE, seed);
    let decoded = decode_source_symbols(&decoder, &build_received_from_emitted(&decoder, &emitted));
    let recovered = flatten_source_symbols(&decoded, payload.len());

    assert_eq!(
        recovered, payload,
        "{case_name} canonical roundtrip must recover the exact payload bytes"
    );

    CanonicalVectorGolden {
        case_name: case_name.to_string(),
        payload_size,
        symbol_size: CANONICAL_SYMBOL_SIZE,
        k: expected_k,
        k_prime: decoder.params().k_prime,
        repair_count: CANONICAL_REPAIR_COUNT,
        packet_count: emitted.len(),
        packets: emitted
            .into_iter()
            .map(|symbol| CanonicalPacketGolden {
                esi: symbol.esi,
                kind: if symbol.is_source { "source" } else { "repair" },
                degree: symbol.degree,
                data_hex: hex_lower(&symbol.data),
            })
            .collect(),
    }
}

#[test]
fn mr_repair_backed_roundtrip_preserves_original_source() {
    let k = 12;
    let symbol_size = 48;
    let seed = 0x1357_2468_9ABC_DEF0;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).expect("encoder");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let dropped = [1usize, 4, 8, 10];

    let received = build_received_symbols(&encoder, &decoder, &source, &dropped, dropped.len() + 2);
    let decoded = decode_source_symbols(&decoder, &received);

    assert_eq!(
        decoded, source,
        "repair-backed roundtrip must recover the original source symbols"
    );
}

#[test]
fn mr_extra_repair_symbols_do_not_change_decoded_payload() {
    let k = 10;
    let symbol_size = 64;
    let seed = 0x0BAD_5EED_F00D_CAFE;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).expect("encoder");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let dropped = [0usize, 3, 7];

    let baseline = build_received_symbols(&encoder, &decoder, &source, &dropped, dropped.len() + 1);
    let augmented =
        build_received_symbols(&encoder, &decoder, &source, &dropped, dropped.len() + 5);

    let baseline_decoded = decode_source_symbols(&decoder, &baseline);
    let augmented_decoded = decode_source_symbols(&decoder, &augmented);

    assert_eq!(
        baseline_decoded, source,
        "baseline repair-backed decode must preserve source identity"
    );
    assert_eq!(
        augmented_decoded, baseline_decoded,
        "adding repair symbols must not change the decoded payload"
    );
}

#[test]
fn mr_received_symbol_permutation_preserves_decoded_payload() {
    let k = 11;
    let symbol_size = 40;
    let seed = 0xA11C_E5E0_1234_5678;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).expect("encoder");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let dropped = [2usize, 5, 9];

    let original = build_received_symbols(&encoder, &decoder, &source, &dropped, dropped.len() + 3);
    let mut permuted = original.clone();
    permute_symbols(&mut permuted, seed ^ 0x55AA_33CC);

    let original_decoded = decode_source_symbols(&decoder, &original);
    let permuted_decoded = decode_source_symbols(&decoder, &permuted);

    assert_eq!(
        original_decoded, source,
        "original receive order must decode to the source payload"
    );
    assert_eq!(
        permuted_decoded, original_decoded,
        "reordering received symbols must not change the decoded payload"
    );
}

#[test]
fn canonical_roundtrip_vectors_scrubbed() {
    // br-asupersync-c12bcb: cover the smallest legal K, both sides of the
    // lower K'=10 -> 12 ladder transition (10/11), and the larger
    // K'=257 -> 263 transition (257/258) with one exact-fit and one
    // partial-last-symbol payload.
    let vectors = [
        ("k1_payload7", 7usize, 1usize, 0xC12B_CB01_u64),
        ("k10_payload80", 80, 10, 0xC12B_CB0A),
        ("k11_payload81", 81, 11, 0xC12B_CB0B),
        ("k256_payload2048", 2048, 256, 0xC12B_CC00),
        ("k257_payload2056", 2056, 257, 0xC12B_CC01),
        ("k258_payload2057", 2057, 258, 0xC12B_CC02),
    ]
    .into_iter()
    .map(|(case_name, payload_size, expected_k, seed)| {
        canonical_roundtrip_case(case_name, payload_size, expected_k, seed)
    })
    .collect::<Vec<_>>();

    assert_json_snapshot!("canonical_roundtrip_vectors_scrubbed", vectors);
}
