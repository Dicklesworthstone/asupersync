#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

const K_CANDIDATES: &[usize] = &[4, 7, 10, 17, 33, 42, 64, 96, 128];
const SYMBOL_SIZE_CANDIDATES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128];
const LOSS_RATES: &[LossRate] = &[
    LossRate {
        label: "10%",
        percent: 10,
    },
    LossRate {
        label: "30%",
        percent: 30,
    },
    LossRate {
        label: "50%",
        percent: 50,
    },
];
const MAX_SOURCE_BYTES: usize = 16 * 1024;
const MIN_REPAIR_SLACK: usize = 4;

#[derive(Debug, Arbitrary)]
struct RandomLossInput {
    k_selector: u16,
    symbol_size_selector: u16,
    seed: u64,
    loss_seed: u64,
    repair_slack_selector: u8,
    payload: Vec<u8>,
    order: PacketOrder,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum PacketOrder {
    Preserve,
    Reverse,
    Rotate { by: u16 },
    AlternatingEdges,
}

#[derive(Debug, Clone, Copy)]
struct LossRate {
    label: &'static str,
    percent: u8,
}

fuzz_target!(|input: RandomLossInput| {
    let k = select_k(input.k_selector);
    let symbol_size = select_symbol_size(input.symbol_size_selector, k);
    let source = build_source_block(&input.payload, k, symbol_size, input.seed);
    let Some(encoder) = SystematicEncoder::new(&source, symbol_size, input.seed) else {
        return;
    };
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);

    for (rate_index, rate) in LOSS_RATES.iter().copied().enumerate() {
        assert_random_loss_decodes(&input, rate_index, rate, &decoder, &encoder, &source);
    }
});

fn select_k(selector: u16) -> usize {
    K_CANDIDATES[usize::from(selector) % K_CANDIDATES.len()]
}

fn select_symbol_size(selector: u16, k: usize) -> usize {
    let selected = SYMBOL_SIZE_CANDIDATES[usize::from(selector) % SYMBOL_SIZE_CANDIDATES.len()];
    let max_symbol_size = (MAX_SOURCE_BYTES / k).max(1);

    if selected <= max_symbol_size {
        return selected;
    }

    SYMBOL_SIZE_CANDIDATES
        .iter()
        .copied()
        .filter(|candidate| *candidate <= max_symbol_size)
        .max()
        .unwrap_or(1)
}

fn build_source_block(payload: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let salt = seed.to_le_bytes();

    (0..k)
        .map(|row| {
            (0..symbol_size)
                .map(|col| {
                    let pattern =
                        (row as u8).wrapping_mul(37) ^ (col as u8).wrapping_mul(19) ^ 0xA5;
                    payload
                        .get((row * symbol_size + col) % payload.len().max(1))
                        .copied()
                        .unwrap_or(pattern)
                        ^ pattern
                        ^ salt[(row + col) % salt.len()]
                })
                .collect()
        })
        .collect()
}

fn assert_random_loss_decodes(
    input: &RandomLossInput,
    rate_index: usize,
    rate: LossRate,
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
) {
    let k = source.len();
    let repair_count = repair_count_for_loss(k, rate.percent, input.repair_slack_selector);
    let transmitted = build_transmitted_symbols(decoder, encoder, source, repair_count);
    let mut received_payload =
        apply_random_loss(transmitted, input.loss_seed, rate_index, rate.percent);
    apply_order(&mut received_payload, input.order);

    if received_payload.len() < k {
        return;
    }

    let available = received_payload.len();
    let mut received = decoder.constraint_symbols();
    received.extend(received_payload);

    let decoded = decoder.decode(&received).unwrap_or_else(|err| {
        panic!(
            "RaptorQ decode must recover after {} random loss when available={} >= K={}: {err:?}",
            rate.label, available, k
        )
    });

    assert_eq!(
        decoded.source, source,
        "RaptorQ decode must reconstruct the original source after {} random loss with available={} >= K={}",
        rate.label, available, k
    );
}

fn repair_count_for_loss(k: usize, loss_percent: u8, slack_selector: u8) -> usize {
    let kept_percent = usize::from(100u8.saturating_sub(loss_percent)).max(1);
    let loss_percent = usize::from(loss_percent);
    let expected_repair_need = (k * loss_percent).div_ceil(kept_percent);
    let max_slack = (k / 2).clamp(MIN_REPAIR_SLACK, 32);
    let slack = usize::from(slack_selector) % (max_slack + 1);

    expected_repair_need + MIN_REPAIR_SLACK + slack
}

fn build_transmitted_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    repair_count: usize,
) -> Vec<ReceivedSymbol> {
    let mut transmitted = Vec::with_capacity(source.len() + repair_count);
    transmitted.extend(
        source
            .iter()
            .enumerate()
            .map(|(esi, data)| ReceivedSymbol::source(esi as u32, data.clone())),
    );

    let base = u32::try_from(source.len()).expect("bounded fuzz K fits in u32");
    for repair_offset in 0..repair_count {
        let Some(esi) = u32::try_from(repair_offset)
            .ok()
            .and_then(|offset| base.checked_add(offset))
        else {
            break;
        };
        let Ok((columns, coefficients)) = decoder.repair_equation(esi) else {
            continue;
        };
        transmitted.push(ReceivedSymbol::repair(
            esi,
            columns,
            coefficients,
            encoder.repair_symbol(esi),
        ));
    }

    transmitted
}

fn apply_random_loss(
    transmitted: Vec<ReceivedSymbol>,
    loss_seed: u64,
    rate_index: usize,
    loss_percent: u8,
) -> Vec<ReceivedSymbol> {
    let stream = (rate_index as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut rng = LossRng::new(loss_seed ^ stream);

    transmitted
        .into_iter()
        .filter(|_| rng.next_percent() >= loss_percent)
        .collect()
}

fn apply_order(symbols: &mut Vec<ReceivedSymbol>, order: PacketOrder) {
    match order {
        PacketOrder::Preserve => {}
        PacketOrder::Reverse => symbols.reverse(),
        PacketOrder::Rotate { by } => {
            if !symbols.is_empty() {
                let len = symbols.len();
                symbols.rotate_left(usize::from(by) % len);
            }
        }
        PacketOrder::AlternatingEdges => {
            let mut reordered = Vec::with_capacity(symbols.len());
            let mut low = 0usize;
            let mut high = symbols.len();
            while low < high {
                reordered.push(symbols[low].clone());
                low += 1;
                if low < high {
                    high -= 1;
                    reordered.push(symbols[high].clone());
                }
            }
            *symbols = reordered;
        }
    }
}

struct LossRng {
    state: u64,
}

impl LossRng {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x.max(1);
        x
    }

    fn next_percent(&mut self) -> u8 {
        (self.next_u64() % 100) as u8
    }
}
