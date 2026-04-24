//! Metamorphic roundtrip coverage for the RaptorQ systematic encoder/decoder pair.

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::util::DetRng;

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

fn permute_symbols(symbols: &mut [ReceivedSymbol], seed: u64) {
    let mut rng = DetRng::new(seed);
    for idx in (1..symbols.len()).rev() {
        let swap_idx = (rng.next_u32() as usize) % (idx + 1);
        symbols.swap(idx, swap_idx);
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
