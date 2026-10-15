//! RFC 6330 large-block decode correctness (bead bd-3uox5).
//!
//! `tests/raptorq_decode_correctness_matrix.rs` covers small blocks (K <= 40)
//! whose loss is recovered largely by peeling. Larger source blocks drive the
//! `InactivationDecoder` into its dense-core / inactivation solver regime — a
//! distinct code path that peeling-only cases never reach. This harness proves
//! byte-identical recovery for larger K under scattered, burst, and
//! full-source-erasure loss, including the solver-heavy zero-systematic case.
//!
//! Verifiable by construction (recovered source must equal the original), fixed
//! `DetRng` seeds, structured JSON line per scenario.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_decode_large_block_correctness -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use asupersync::util::DetRng;

const OBJECT_ID_HIGH: u64 = 0x7E57_B10C_C0DE_0001;
const OBJECT_ID_LOW: u64 = 0x0FF1_CE10_2030_4050;

fn make_source(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(seed);
    (0..k)
        .map(|_| {
            (0..symbol_size)
                .map(|_| (rng.next_u64() & 0xFF) as u8)
                .collect()
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum Loss {
    Scattered(&'static [usize]),
    Burst { start: usize, len: usize },
    AllSource,
}

struct Scenario {
    id: &'static str,
    k: usize,
    symbol_size: usize,
    seed: u64,
    sbn: u8,
    loss: Loss,
    extra_repairs: usize,
}

fn dropped_indices(loss: Loss, k: usize) -> Vec<usize> {
    match loss {
        Loss::Scattered(list) => list.iter().copied().filter(|&i| i < k).collect(),
        Loss::Burst { start, len } => (start..start + len).filter(|&i| i < k).collect(),
        Loss::AllSource => (0..k).collect(),
    }
}

fn build_received(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    dropped: &[usize],
    extra_repairs: usize,
) -> (Vec<ReceivedSymbol>, usize) {
    let k = source.len();
    let l = decoder.params().l;
    let mut received = decoder.constraint_symbols();

    let mut survived = 0usize;
    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
            survived += 1;
        }
    }

    let repair_upper = (l + extra_repairs) as u32;
    for esi in (k as u32)..repair_upper {
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair_equation esi={esi} failed: {err:?}"));
        received.push(ReceivedSymbol::repair(
            esi,
            columns,
            coefficients,
            encoder.repair_symbol(esi),
        ));
    }

    (received, survived)
}

fn run_scenario(scenario: &Scenario) {
    let source = make_source(scenario.k, scenario.symbol_size, scenario.seed);
    let encoder = SystematicEncoder::new(&source, scenario.symbol_size, scenario.seed)
        .unwrap_or_else(|| panic!("[{}] encoder construction must succeed", scenario.id));
    let decoder = InactivationDecoder::new(scenario.k, scenario.symbol_size, scenario.seed);

    let dropped = dropped_indices(scenario.loss, scenario.k);
    let (received, survived) = build_received(
        &encoder,
        &decoder,
        &source,
        &dropped,
        scenario.extra_repairs,
    );

    let object_id = ObjectId::new(OBJECT_ID_HIGH, OBJECT_ID_LOW);
    let success = decoder
        .decode_with_proof(&received, object_id, scenario.sbn)
        .unwrap_or_else(|(err, _proof)| {
            panic!(
                "[{}] decode_with_proof must recover the source: {err:?}",
                scenario.id
            )
        });

    assert_eq!(
        success.result.source, source,
        "[{}] recovered source bytes must equal the original",
        scenario.id
    );

    println!(
        "{{\"schema\":\"raptorq-decode-large-v1\",\"scenario_id\":\"{}\",\"seed\":{},\"k\":{},\"symbol_size\":{},\"sbn\":{},\"loss_pattern\":\"{:?}\",\"dropped\":{},\"survived_source\":{},\"received_total\":{},\"outcome\":\"ok\"}}",
        scenario.id,
        scenario.seed,
        scenario.k,
        scenario.symbol_size,
        scenario.sbn,
        scenario.loss,
        dropped.len(),
        survived,
        received.len()
    );
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        id: "RQ-DEC-LARGE-SCATTERED-K64",
        k: 64,
        symbol_size: 16,
        seed: 0x2468_ACE0_1357_9BDF,
        sbn: 5,
        loss: Loss::Scattered(&[1, 9, 17, 23, 31, 44, 58, 63]),
        extra_repairs: 6,
    },
    Scenario {
        id: "RQ-DEC-LARGE-BURST-K128",
        k: 128,
        symbol_size: 16,
        seed: 0x1359_7BDF_2468_ACE0,
        sbn: 88,
        loss: Loss::Burst { start: 40, len: 20 },
        extra_repairs: 8,
    },
    Scenario {
        id: "RQ-DEC-LARGE-ALL-SOURCE-K50",
        k: 50,
        symbol_size: 16,
        seed: 0xACE0_2468_9BDF_1357,
        sbn: 17,
        loss: Loss::AllSource,
        // Full-source erasure is the rank-stressing regime: every recovered
        // symbol comes from repair equations, so supply generous overhead.
        extra_repairs: 32,
    },
];

#[test]
fn raptorq_large_block_decode_recovers_every_scenario() {
    for scenario in SCENARIOS {
        run_scenario(scenario);
    }
}
