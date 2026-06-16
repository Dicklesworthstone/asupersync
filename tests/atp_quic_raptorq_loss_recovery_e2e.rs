//! RaptorQ-over-QUIC datagram loss recovery — end-to-end (`arq-quic-epic-b0k8qo.2.4`, "B4" slice).
//!
//! Proves the epic's headline data-plane property without the (still in-flight)
//! B2/B3 coroutines: a buffer is RaptorQ-encoded into source + repair symbols,
//! each symbol is sprayed over the QUIC DATAGRAM plane via the A6
//! [`QuicConnection`] + the `symbol_datagram` bridge, some **source** symbols are
//! "lost" in transit, and the surviving **K-of-N** symbols recover the original
//! buffer through the RaptorQ decoder — and, conversely, fewer than K symbols
//! fail to decode (fountain threshold, fail closed).
//!
//! It composes real RaptorQ (`EncodingPipeline` / `DecodingPipeline`) + the A6
//! deterministic loopback + the `Symbol`↔datagram bridge. Scope: a single source
//! block (the multi-block / directory-tree / SHA-256 verify / atomic commit
//! pipeline is B4 proper, driven by the B2/B3 sender/receiver coroutines). Public
//! API only.

#![allow(clippy::cast_possible_truncation)]

use std::time::Duration;

use asupersync::config::EncodingConfig;
use asupersync::cx::Cx;
use asupersync::decoding::{DecodingConfig, DecodingPipeline};
use asupersync::encoding::EncodingPipeline;
use asupersync::net::atp::transport_quic::{envelope_to_symbol, recv_symbol_envelope, send_symbol};
use asupersync::net::quic_native::{
    DEFAULT_MAX_PACKET_BYTES, NativeQuicConnectionConfig, QuicConnection, establish_loopback,
    pump_until_idle,
};
use asupersync::security::AuthenticatedSymbol;
use asupersync::security::tag::AuthenticationTag;
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolKind};

const SYMBOL_SIZE: u16 = 256;
const MAX_BLOCK_SIZE: usize = 8192;
/// 2048 / 256 = 8 source symbols in a single source block.
const DATA_LEN: usize = 2048;

fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Byte-varied payload so erasure recovery is non-vacuous (a constant buffer
/// would let a wrong decode still "match").
fn make_data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u64).wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect()
}

fn pool() -> SymbolPool {
    SymbolPool::new(PoolConfig::new(SYMBOL_SIZE, 64, 256, true, 64))
}

fn encoding_config() -> EncodingConfig {
    EncodingConfig {
        symbol_size: SYMBOL_SIZE,
        max_block_size: MAX_BLOCK_SIZE,
        repair_overhead: 1.0,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

fn decoding_config() -> DecodingConfig {
    DecodingConfig {
        symbol_size: SYMBOL_SIZE,
        max_block_size: MAX_BLOCK_SIZE,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: 0,
        block_timeout: Duration::from_secs(30),
        verify_auth: false,
    }
}

fn established_pair(cx: &Cx) -> (QuicConnection, QuicConnection) {
    let cfg = NativeQuicConnectionConfig::default();
    let mut client = QuicConnection::client(cfg);
    let mut server = QuicConnection::server(cfg);
    client.record_verified_server_identity();
    establish_loopback(cx, &mut client, &mut server).expect("loopback establishes");
    (client, server)
}

/// RaptorQ-encode `data` for `object_id` into source + `repair_count` repair
/// symbols.
fn encode_symbols(object_id: ObjectId, data: &[u8], repair_count: usize) -> Vec<Symbol> {
    let mut encoder = EncodingPipeline::new(encoding_config(), pool());
    encoder
        .encode_with_repair(object_id, data, repair_count)
        .map(|res| res.expect("encode symbol").into_symbol())
        .collect()
}

/// Spray `symbols` over the QUIC datagram plane (client → server) and collect the
/// symbols the server reassembles. `object_id` reconstructs each `SymbolId` — in
/// the real receiver the manifest resolves it from the envelope's
/// `transfer_tag`/`entry`.
fn spray_and_collect(
    cx: &Cx,
    client: &mut QuicConnection,
    server: &mut QuicConnection,
    symbols: &[Symbol],
    object_id: ObjectId,
) -> Vec<Symbol> {
    for s in symbols {
        send_symbol(cx, client, s, 1, 0, None).expect("send symbol");
    }
    pump_until_idle(cx, client, server, DEFAULT_MAX_PACKET_BYTES, 1_000).expect("pump");
    let mut received = Vec::new();
    while let Some(env) = recv_symbol_envelope(server, false).expect("decode envelope") {
        received.push(envelope_to_symbol(&env, object_id));
    }
    received
}

/// Feed `symbols` into a fresh RaptorQ decoder for the single-block object and
/// attempt to recover the original bytes.
fn decode(
    object_id: ObjectId,
    data_len: usize,
    block_k: usize,
    symbols: &[Symbol],
) -> Result<Vec<u8>, ()> {
    let params = ObjectParams::new(
        object_id,
        data_len as u64,
        SYMBOL_SIZE,
        1,
        u16::try_from(block_k).expect("k fits u16"),
    );
    let mut pipeline = DecodingPipeline::new(decoding_config());
    pipeline.set_object_params(params).expect("set params");
    for s in symbols {
        let auth = AuthenticatedSymbol::from_parts(s.clone(), AuthenticationTag::zero());
        let _ = pipeline.feed(auth).expect("feed symbol");
    }
    pipeline.into_data().map_err(|_| ())
}

#[test]
fn raptorq_symbols_recover_over_quic_datagrams_with_source_loss() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);
    let object_id = ObjectId::from_u128(0xA7);
    let data = make_data(DATA_LEN);
    let block_k = DATA_LEN.div_ceil(usize::from(SYMBOL_SIZE)); // 8

    // 8 source + 8 repair = 16 symbols.
    let symbols = encode_symbols(object_id, &data, 8);
    assert!(symbols.len() >= block_k, "encoded at least K symbols");

    // Datagram loss: drop 4 SOURCE symbols in transit so the survivors MUST use
    // repair symbols to reconstruct them (16 − 4 = 12 ≥ K = 8, +4 overhead).
    let mut sent = Vec::new();
    let mut dropped_source = 0;
    for s in &symbols {
        if matches!(s.kind(), SymbolKind::Source) && dropped_source < 4 {
            dropped_source += 1;
            continue; // this datagram is "lost"
        }
        sent.push(s.clone());
    }
    assert_eq!(dropped_source, 4, "dropped exactly 4 source symbols");

    let received = spray_and_collect(&cx, &mut client, &mut server, &sent, object_id);
    assert_eq!(
        received.len(),
        sent.len(),
        "bridge delivered every sent symbol"
    );
    assert_eq!(server.datagrams_received(), sent.len() as u64);

    let decoded = decode(object_id, DATA_LEN, block_k, &received)
        .expect("K-of-N survivors recover the object despite the lost source symbols");
    assert_eq!(decoded, data, "recovered bytes match the original exactly");
}

#[test]
fn below_threshold_symbol_count_fails_to_decode() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);
    let object_id = ObjectId::from_u128(0xB8);
    let data = make_data(DATA_LEN);
    let block_k = DATA_LEN.div_ceil(usize::from(SYMBOL_SIZE)); // 8

    let symbols = encode_symbols(object_id, &data, 8);
    // Deliver only K − 1 symbols — below the fountain threshold.
    let sent: Vec<Symbol> = symbols.into_iter().take(block_k - 1).collect();
    let received = spray_and_collect(&cx, &mut client, &mut server, &sent, object_id);
    assert_eq!(received.len(), block_k - 1);

    assert!(
        decode(object_id, DATA_LEN, block_k, &received).is_err(),
        "fewer than K symbols must not decode (fountain threshold, fail closed)"
    );
}
