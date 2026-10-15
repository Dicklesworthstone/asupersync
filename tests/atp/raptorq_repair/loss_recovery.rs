use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use serde::Serialize;

const CASE_ID: &str = "ATP-NR9-RQ-REPAIR-LOSS-V1";
const K: usize = 8;
const SYMBOL_SIZE: usize = 32;
const SEED: u64 = 20_260_524;
const LOST_SOURCE_ESIS: &[usize] = &[1, 2, 3, 4, 6];
const REPAIR_SYMBOLS_SENT: usize = 32;

#[derive(Debug, Serialize)]
struct RepairRecoveryReport {
    schema_version: &'static str,
    case_id: &'static str,
    transfer_shape: &'static str,
    seed: u64,
    k: usize,
    symbol_size: usize,
    source_symbols_total: usize,
    source_symbols_lost: &'static [usize],
    source_symbols_received: usize,
    repair_symbols_sent: usize,
    repair_esi_start: u32,
    repair_esi_end_exclusive: u32,
    pre_repair_failure: &'static str,
    pre_repair_failure_recoverable: bool,
    decode_status: &'static str,
    recovered_source_bytes: usize,
    recovered_source_digest: String,
    replay_ref: &'static str,
}

#[test]
fn burst_loss_recovers_from_real_raptorq_repair_symbols() {
    let source = make_source_block();
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED)
        .expect("canonical source block should create a systematic encoder");
    let sparse_decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let repair_decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);

    let sparse_received = received_without_lost_sources(&sparse_decoder, &source);
    let sparse_failure = sparse_decoder
        .decode(&sparse_received)
        .expect_err("source loss without repair symbols should not decode");
    assert!(
        sparse_failure.is_recoverable(),
        "pre-repair failure should be retryable with repair symbols: {sparse_failure:?}",
    );

    let mut repair_received = received_without_lost_sources(&repair_decoder, &source);
    repair_received.extend(repair_symbols(
        &repair_decoder,
        &encoder,
        K as u32,
        REPAIR_SYMBOLS_SENT,
    ));
    assert!(
        repair_received.iter().any(|symbol| !symbol.is_source),
        "repair scenario must include real nonsystematic RaptorQ repair equations",
    );

    let decoded = repair_decoder
        .decode(&repair_received)
        .expect("repair symbols should recover the ATP transfer payload");
    assert_eq!(decoded.source, source);

    let report = RepairRecoveryReport {
        schema_version: "atp-raptorq-repair-proof-v1",
        case_id: CASE_ID,
        transfer_shape: "constraints+partial-source+repair-symbols",
        seed: SEED,
        k: K,
        symbol_size: SYMBOL_SIZE,
        source_symbols_total: K,
        source_symbols_lost: LOST_SOURCE_ESIS,
        source_symbols_received: K - LOST_SOURCE_ESIS.len(),
        repair_symbols_sent: REPAIR_SYMBOLS_SENT,
        repair_esi_start: K as u32,
        repair_esi_end_exclusive: (K + REPAIR_SYMBOLS_SENT) as u32,
        pre_repair_failure: "recoverable_decode_failure",
        pre_repair_failure_recoverable: sparse_failure.is_recoverable(),
        decode_status: "recovered",
        recovered_source_bytes: decoded.source.iter().map(Vec::len).sum(),
        recovered_source_digest: fnv1a64_source_digest(&decoded.source),
        replay_ref: "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p9 cargo test -p asupersync --test atp_raptorq_repair_e2e",
    };

    assert_eq!(
        render_report(&report),
        include_str!("loss_recovery.golden.json"),
        "RaptorQ repair recovery evidence should remain deterministic",
    );
}

fn make_source_block() -> Vec<Vec<u8>> {
    let seed_term = (SEED as usize % 251) * 17;
    (0..K)
        .map(|esi| {
            (0..SYMBOL_SIZE)
                .map(|offset| {
                    ((esi * 73 + offset * 41 + seed_term + (esi ^ offset) * 11 + 0x5A) % 256) as u8
                })
                .collect()
        })
        .collect()
}

fn received_without_lost_sources(
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
) -> Vec<ReceivedSymbol> {
    let mut received = decoder.constraint_symbols();
    for (esi, data) in source.iter().enumerate() {
        if !LOST_SOURCE_ESIS.contains(&esi) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }
    received
}

fn repair_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    first_esi: u32,
    count: usize,
) -> Vec<ReceivedSymbol> {
    (first_esi..first_esi + count as u32)
        .map(|esi| {
            let (columns, coefficients) = decoder
                .repair_equation(esi)
                .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"));
            let data = encoder.repair_symbol(esi);
            ReceivedSymbol::repair(esi, columns, coefficients, data)
        })
        .collect()
}

fn fnv1a64_source_digest(source: &[Vec<u8>]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for (esi, symbol) in source.iter().enumerate() {
        hash ^= esi as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        for byte in symbol {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    format!("fnv1a64:{hash:016x}")
}

fn render_report(report: &RepairRecoveryReport) -> String {
    let mut json =
        serde_json::to_string_pretty(report).expect("repair recovery report should serialize");
    json.push('\n');
    json
}
