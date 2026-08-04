//! br-asupersync-2l21sv: regression proof that the public low-level
//! `EncodingPipeline` -> `DecodingPipeline` round-trip works for downstream
//! consumers.
//!
//! The defect report (frankenjax, asupersync 0.3.4) showed that code
//! IDENTICAL to the in-crate unit test `decoding::tests::
//! decode_roundtrip_sources_only` failed from a downstream crate with
//! `InsufficientSymbols { have: N, need: N }` at every K, while the same code
//! passed under in-crate `cargo test`. The only `cfg(test)`/`cfg(not(test))`
//! divergence in the decode path is `raptorq::decoder::bypass_governance`,
//! which is hardwired `false` for every non-test build and cannot be
//! bypassed by downstream users.
//!
//! This is a public-API integration test, so it compiles the library with
//! `cfg(test)` OFF — the decoder governance layer here is EXACTLY what
//! external crates get. If the production decode path cannot round-trip a
//! trivially-decodable systematic block, these tests are red.
//!
//! Auth posture: per br-asupersync-b1fojq the decode default is fail-closed
//! (`verify_auth: true`). These tests exercise the erasure-only lane, so they
//! opt out explicitly with `verify_auth: false` exactly like the original
//! reporter did (the failure reproduced with both postures at the time).

use std::time::Duration;

use asupersync::EncodingConfig;
use asupersync::decoding::{DecodingConfig, DecodingPipeline};
use asupersync::encoding::EncodingPipeline;
use asupersync::security::AuthenticatedSymbol;
use asupersync::security::tag::AuthenticationTag;
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::symbol::{ObjectId, ObjectParams, Symbol};

const SYMBOL_SIZE: u16 = 256;

fn pool() -> SymbolPool {
    SymbolPool::new(PoolConfig {
        symbol_size: SYMBOL_SIZE,
        initial_size: 80,
        max_size: 320,
        allow_growth: true,
        growth_increment: 64,
    })
}

fn encoding_config(repair_overhead: f64, max_block_size: usize) -> EncodingConfig {
    EncodingConfig {
        symbol_size: SYMBOL_SIZE,
        max_block_size,
        repair_overhead,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

fn decoding_config(max_block_size: usize) -> DecodingConfig {
    DecodingConfig {
        symbol_size: SYMBOL_SIZE,
        max_block_size,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: 0,
        block_timeout: Duration::from_secs(30),
        // Explicit erasure-only opt-out (br-asupersync-b1fojq): the round-trip
        // under test is the unauthenticated lane the reporter exercised.
        verify_auth: false,
    }
}

fn feed_all(decoder: &mut DecodingPipeline, symbols: Vec<Symbol>) {
    for symbol in symbols {
        let auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());
        decoder.feed(auth).expect("feed symbol");
    }
}

/// The exact minimal repro from the bug report: K=2 via `encode()` with
/// 1.1x repair overhead, decoder params derived from encoder stats.
#[test]
fn bug_report_minimal_repro_k2_encode_with_repair_overhead() {
    let object_id = ObjectId::new(0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321);
    let data = vec![7u8; 512];
    let mut encoder = EncodingPipeline::new(encoding_config(1.1, 1 << 20), pool());
    let symbols: Vec<Symbol> = encoder
        .encode(object_id, &data)
        .map(|res| res.expect("encode").into_symbol())
        .collect();
    let k = encoder.stats().source_symbols;
    assert!(k > 0, "encoder reported zero source symbols");

    let mut decoder = DecodingPipeline::new(decoding_config(1 << 20));
    decoder
        .set_object_params(ObjectParams::new(
            object_id,
            data.len() as u64,
            SYMBOL_SIZE,
            1,
            u16::try_from(k).expect("K fits u16"),
        ))
        .expect("set params");

    feed_all(&mut decoder, symbols);
    let decoded = decoder
        .into_data()
        .expect("decode all-symbols-present round-trip");
    assert_eq!(decoded, data, "decoded bytes differ from source");
}

/// Verbatim public-API port of the in-crate unit test
/// `decoding::tests::decode_roundtrip_sources_only`, which the reporter
/// proved passes in-crate but failed downstream: sources only, no repair.
#[test]
fn decode_roundtrip_sources_only_public_api() {
    let object_id = ObjectId::new(0, 1);
    let data = vec![42u8; 512];
    let mut encoder = EncodingPipeline::new(encoding_config(1.05, 1024), pool());
    let symbols: Vec<Symbol> = encoder
        .encode_with_repair(object_id, &data, 0)
        .map(|res| res.expect("encode").into_symbol())
        .collect();
    let k = encoder.stats().source_symbols;

    let mut decoder = DecodingPipeline::new(decoding_config(1024));
    decoder
        .set_object_params(ObjectParams::new(
            object_id,
            data.len() as u64,
            SYMBOL_SIZE,
            1,
            u16::try_from(k).expect("K fits u16"),
        ))
        .expect("set params");

    feed_all(&mut decoder, symbols);
    let decoded = decoder.into_data().expect("decode sources-only round-trip");
    assert_eq!(decoded, data, "decoded bytes differ from source");
}

/// The reporter observed the failure at every small K. Sweep K = 1,2,4,8,16
/// with all source symbols present plus two repair symbols.
#[test]
fn decode_roundtrip_small_k_sweep() {
    for k in [1usize, 2, 4, 8, 16] {
        let object_id = ObjectId::new(xk_seed(k), k as u64);
        let data: Vec<u8> = (0..k * usize::from(SYMBOL_SIZE))
            .map(|i| (i % 251) as u8)
            .collect();
        let max_block = 1 << 20;
        let mut encoder = EncodingPipeline::new(encoding_config(1.05, max_block), pool());
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 2)
            .map(|res| res.expect("encode").into_symbol())
            .collect();
        let reported_k = encoder.stats().source_symbols;
        assert_eq!(reported_k, k, "encoder K mismatch for k={k}");

        let mut decoder = DecodingPipeline::new(decoding_config(max_block));
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                SYMBOL_SIZE,
                1,
                u16::try_from(reported_k).expect("K fits u16"),
            ))
            .expect("set params");

        feed_all(&mut decoder, symbols);
        let decoded = decoder
            .into_data()
            .unwrap_or_else(|err| panic!("decode failed at k={k}: {err:?}"));
        assert_eq!(decoded, data, "decoded bytes differ from source at k={k}");
    }
}

/// Helper kept out of the loop for clarity: deterministic per-K object seed.
const fn xk_seed(k: usize) -> u64 {
    0x2121_5700 ^ (k as u64)
}
