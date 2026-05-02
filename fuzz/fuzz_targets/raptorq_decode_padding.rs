#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

const K_CANDIDATES: &[usize] = &[2, 3, 4, 7, 10, 17, 33, 50];
const SYMBOL_SIZE_CANDIDATES: &[usize] = &[2, 3, 4, 7, 8, 16, 32, 64];
const MAX_REPAIR_SLACK: usize = 8;

#[derive(Debug, Arbitrary)]
struct DecodePaddingInput {
    k_selector: u8,
    symbol_size_selector: u8,
    padding_selector: u16,
    seed: u64,
    repair_slack: u8,
    payload: Vec<u8>,
    reorder: PacketOrder,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum PacketOrder {
    Preserve,
    Reverse,
    Rotate { by: u8 },
}

fuzz_target!(|input: DecodePaddingInput| {
    let k = K_CANDIDATES[usize::from(input.k_selector) % K_CANDIDATES.len()];
    let symbol_size = SYMBOL_SIZE_CANDIDATES
        [usize::from(input.symbol_size_selector) % SYMBOL_SIZE_CANDIDATES.len()];
    let padding_len = usize::from(input.padding_selector) % (symbol_size - 1) + 1;
    let expected_len = k * symbol_size - padding_len;
    let source =
        build_padded_source_block(&input.payload, expected_len, k, symbol_size, input.seed);
    let expected_payload = flatten_source_symbols(&source, expected_len);

    assert_final_symbol_is_zero_padded(&source, padding_len);

    let Some(encoder) = SystematicEncoder::new(&source, symbol_size, input.seed) else {
        return;
    };
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);

    let baseline = decoder
        .decode(&all_source_symbols(&decoder, &source))
        .expect("all systematic symbols with a padded final symbol must decode");
    assert_payload_without_padding(&baseline.source, &expected_payload, expected_len);

    let mut received = missing_final_source_symbols(
        &decoder,
        &encoder,
        &source,
        usize::from(input.repair_slack) % (MAX_REPAIR_SLACK + 1),
    );
    apply_order(&mut received, input.reorder);

    if let Ok(decoded) = decoder.decode(&received) {
        assert_payload_without_padding(&decoded.source, &expected_payload, expected_len);
    }
});

fn build_padded_source_block(
    payload: &[u8],
    expected_len: usize,
    k: usize,
    symbol_size: usize,
    seed: u64,
) -> Vec<Vec<u8>> {
    let payload = deterministic_payload(payload, expected_len, seed);
    let mut source = Vec::with_capacity(k);

    for chunk in payload.chunks(symbol_size) {
        let mut symbol = vec![0u8; symbol_size];
        symbol[..chunk.len()].copy_from_slice(chunk);
        source.push(symbol);
    }

    source.resize_with(k, || vec![0u8; symbol_size]);
    source
}

fn deterministic_payload(payload: &[u8], expected_len: usize, seed: u64) -> Vec<u8> {
    let salt = seed.to_le_bytes();
    (0..expected_len)
        .map(|idx| {
            let fallback = (idx as u8).wrapping_mul(37) ^ salt[idx % salt.len()] ^ 0xA5;
            payload
                .get(idx % payload.len().max(1))
                .copied()
                .unwrap_or(fallback)
                ^ fallback
        })
        .collect()
}

fn all_source_symbols(decoder: &InactivationDecoder, source: &[Vec<u8>]) -> Vec<ReceivedSymbol> {
    let mut received = decoder.constraint_symbols();
    received.extend(
        source
            .iter()
            .enumerate()
            .map(|(esi, data)| ReceivedSymbol::source(esi as u32, data.clone())),
    );
    received
}

fn missing_final_source_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    repair_slack: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut received = decoder.constraint_symbols();

    received.extend(
        source
            .iter()
            .take(k.saturating_sub(1))
            .enumerate()
            .map(|(esi, data)| ReceivedSymbol::source(esi as u32, data.clone())),
    );

    let repair_count = k + repair_slack;
    for repair_offset in 0..repair_count {
        let esi = k as u32 + repair_offset as u32;
        let Ok((columns, coefficients)) = decoder.repair_equation(esi) else {
            continue;
        };
        let data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }

    received
}

fn apply_order(symbols: &mut [ReceivedSymbol], order: PacketOrder) {
    match order {
        PacketOrder::Preserve => {}
        PacketOrder::Reverse => symbols.reverse(),
        PacketOrder::Rotate { by } => {
            if !symbols.is_empty() {
                symbols.rotate_left(usize::from(by) % symbols.len());
            }
        }
    }
}

fn assert_final_symbol_is_zero_padded(source: &[Vec<u8>], padding_len: usize) {
    let final_symbol = source
        .last()
        .expect("fuzz source block always has at least one symbol");
    let padding_start = final_symbol.len() - padding_len;
    assert!(
        final_symbol[padding_start..].iter().all(|byte| *byte == 0),
        "final source symbol must contain explicit zero padding"
    );
}

fn assert_payload_without_padding(
    decoded_source: &[Vec<u8>],
    expected_payload: &[u8],
    expected_len: usize,
) {
    let recovered = flatten_source_symbols(decoded_source, expected_len);
    assert_eq!(
        recovered.len(),
        expected_len,
        "recovered payload must stop at original length"
    );
    assert_eq!(
        recovered, expected_payload,
        "decoded payload must not include final-symbol padding bytes"
    );
}

fn flatten_source_symbols(source: &[Vec<u8>], expected_len: usize) -> Vec<u8> {
    source
        .iter()
        .flatten()
        .copied()
        .take(expected_len)
        .collect()
}
