//! RaptorQ pipeline send → receive round-trip conformance (bd-3uox5).
//!
//! VEIN: `RaptorQReceiver::receive_object` (src/raptorq/pipeline.rs:315) had
//! ZERO end-to-end integration coverage. The only `receive_object` reference in
//! `tests/` (raptorq_receive_authentication_summary_predicates.rs) constructs
//! `ReceiveOutcome`/`ReceiveAuthenticationSummary` *directly* via their public
//! fields and never drives the receive pipeline. The full round-trip exercises
//! only existed as inline `#[cfg(test)]` unit tests in pipeline.rs
//! (`test_send_object_roundtrip_*`), which (a) never run as part of an
//! integration crate and (b) reach the `pub(crate)` `RaptorQSender::new` /
//! `RaptorQReceiver::new` constructors + a module-local `VecSink` that the
//! public surface cannot touch.
//!
//! This crate ports those round-trips to the PUBLIC surface
//! (`RaptorQSenderBuilder` / `RaptorQReceiverBuilder` + the public
//! `transport::sink::CollectingSink` / `transport::stream::VecStream`) and
//! extends them with oracle-free properties the inline tests do not pin:
//!   * symbol accounting identities on `SendOutcome`,
//!   * the systematic property (K source symbols alone decode),
//!   * erasure recovery THROUGH the public receiver (drop a source symbol,
//!     repair reconstructs it — the headline fountain property, previously
//!     proven only against the low-level decoder in raptorq_decoder_metamorphic),
//!   * fail-closed on an under-supplied symbol set (`InsufficientSymbols`),
//!   * foreign-object symbol demux (`params.object_id` filter),
//!   * the no-key authentication posture reported by `ReceiveOutcome`
//!     (sender signs with the all-zero sentinel tag ⇒ `new_verified` records
//!     `verified=false`; the receiver, lacking auth material, reports the
//!     symbols as the unauthenticated sentinel and `authenticated=false`),
//!   * encode determinism (independent senders emit byte-identical streams).
//!
//! `Cx::for_testing()` is gated behind `cfg(any(test, feature="test-internals"))`,
//! so this crate REQUIRES `--features test-internals` (same as
//! raptorq_decoder_metamorphic).
//!
//! RCH (additive, new file — no shared-src edits):
//!   RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
//!     RUSTFLAGS='-D warnings' cargo test -p asupersync \
//!     --features test-internals --test raptorq_pipeline_roundtrip_conformance

use asupersync::config::RaptorQConfig;
use asupersync::cx::Cx;
use asupersync::error::{Error, ErrorKind};
use asupersync::raptorq::{
    RaptorQReceiverBuilder, RaptorQSenderBuilder, ReceiveOutcome, SendOutcome,
};
use asupersync::security::AuthenticatedSymbol;
use asupersync::transport::sink::CollectingSink;
use asupersync::transport::stream::VecStream;
use asupersync::types::{ObjectId, ObjectParams};

const SYMBOL_SIZE: u16 = 256;
/// 2048 / 256 = 8 source symbols in a single source block.
const DATA_LEN: usize = 2048;

/// Default-overhead config (5% repair).
fn default_config() -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = SYMBOL_SIZE;
    config
}

/// Sender config that over-provisions repair so the wire carries spare symbols
/// for erasure recovery.
fn high_repair_config() -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = SYMBOL_SIZE;
    config.encoding.repair_overhead = 2.0;
    config
}

/// Receiver config that decodes greedily. `repair_overhead = 1.0` sets the
/// decode-attempt threshold to exactly K (`required_symbols` =
/// `max(ceil(K * overhead), K)`), so the receiver tries to decode as soon as it
/// has K symbols and keeps retrying as more arrive — the posture that tolerates
/// a lost source symbol. (The decoder math is independent of `repair_overhead`;
/// the knob only gates *when* a block decode is attempted.)
fn decode_greedy_config() -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = SYMBOL_SIZE;
    config.encoding.repair_overhead = 1.0;
    config
}

/// Deterministic, byte-varied payload (uniform data would make erasure recovery
/// vacuous — any decode reproduces a constant).
fn make_data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let v = (i as u64)
                .wrapping_mul(31)
                .wrapping_add(u64::from(seed).wrapping_mul(131));
            (v % 256) as u8
        })
        .collect()
}

/// Single-source-block params describing the encoded object.
fn params_for(object_id: ObjectId, data_len: usize, source_symbols: usize) -> ObjectParams {
    ObjectParams::new(
        object_id,
        data_len as u64,
        SYMBOL_SIZE,
        1,
        source_symbols as u16,
    )
}

/// Build a sender over a `CollectingSink`, send, and return the outcome plus
/// every symbol the encoder placed on the wire.
fn send_collect(
    cx: &Cx,
    config: &RaptorQConfig,
    object_id: ObjectId,
    data: &[u8],
) -> (SendOutcome, Vec<AuthenticatedSymbol>) {
    let mut sender = RaptorQSenderBuilder::new()
        .config(config.clone())
        .transport(CollectingSink::new())
        .build()
        .expect("sender build");
    let outcome = sender
        .send_object(cx, object_id, data)
        .expect("send_object should succeed");
    let symbols = sender.transport_mut().symbols().to_vec();
    (outcome, symbols)
}

/// Build a receiver over a `VecStream` of the supplied symbols and decode.
fn receive(
    cx: &Cx,
    config: &RaptorQConfig,
    params: &ObjectParams,
    symbols: Vec<AuthenticatedSymbol>,
) -> Result<ReceiveOutcome, Error> {
    let mut receiver = RaptorQReceiverBuilder::new()
        .config(config.clone())
        .source(VecStream::new(symbols))
        .build()
        .expect("receiver build");
    receiver.receive_object(cx, params)
}

#[test]
fn roundtrip_all_collected_symbols_reconstructs_object() {
    let cx = Cx::for_testing();
    let config = default_config();
    let object_id = ObjectId::new(0, 7);
    let data = make_data(DATA_LEN, 0x11);

    let (outcome, symbols) = send_collect(&cx, &config, object_id, &data);
    let params = params_for(object_id, data.len(), outcome.source_symbols);

    let recv = receive(&cx, &config, &params, symbols).expect("decode from full symbol set");

    assert!(
        recv.data.len() >= data.len(),
        "decoded buffer never shorter than the object"
    );
    assert_eq!(&recv.data[..data.len()], &data[..], "round-trip fidelity");
    assert!(
        recv.symbols_received >= outcome.source_symbols,
        "decoding consumes at least K source symbols"
    );
    // The summary represents exactly the symbols accepted into the decode set.
    assert_eq!(recv.authentication.total(), recv.symbols_received);
}

#[test]
fn roundtrip_source_symbols_only_reconstructs_object() {
    // Systematic property: the first K (source) symbols alone decode the object,
    // with no repair symbols at all.
    let cx = Cx::for_testing();
    let config = default_config();
    let object_id = ObjectId::new(0, 9);
    let data = make_data(DATA_LEN, 0x22);

    let (outcome, mut symbols) = send_collect(&cx, &config, object_id, &data);
    let params = params_for(object_id, data.len(), outcome.source_symbols);
    symbols.truncate(outcome.source_symbols);
    assert_eq!(
        symbols.len(),
        outcome.source_symbols,
        "feeding exactly the K source symbols"
    );

    let recv = receive(&cx, &config, &params, symbols).expect("source-only decode");

    assert_eq!(&recv.data[..data.len()], &data[..]);
    // Exactly K innovative symbols suffice and all are consumed.
    assert_eq!(recv.symbols_received, outcome.source_symbols);
}

#[test]
fn send_outcome_symbol_accounting_is_consistent() {
    let cx = Cx::for_testing();
    let config = default_config();
    let object_id = ObjectId::new(0, 13);
    let data = make_data(DATA_LEN, 0x33);

    let (outcome, symbols) = send_collect(&cx, &config, object_id, &data);

    let expected_source = data.len().div_ceil(SYMBOL_SIZE as usize);
    assert_eq!(
        outcome.source_symbols, expected_source,
        "single-block K = ceil(len / symbol_size)"
    );
    assert!(outcome.source_symbols > 0);
    assert_eq!(
        outcome.symbols_sent,
        outcome.source_symbols + outcome.repair_symbols,
        "symbols_sent partitions into source + repair"
    );
    assert_eq!(
        symbols.len(),
        outcome.symbols_sent,
        "the CollectingSink observed every transmitted symbol"
    );
    assert_eq!(outcome.object_id, object_id, "outcome echoes the object id");
}

#[test]
fn roundtrip_recovers_from_dropped_source_symbol_via_repair() {
    // Fountain property through the PUBLIC receiver: lose a source symbol, and
    // repair symbols reconstruct it. The encoder is systematic (source-first),
    // so dropping index 0 drops a source symbol; the remaining source set is
    // K-1 < K and therefore CANNOT decode without repair.
    //
    // The sender over-provisions repair (overhead 2.0) so the wire carries more
    // than K symbols; the receiver decodes greedily (threshold = K) so the
    // surviving K-1 source + repair symbols clear the threshold and decode.
    let cx = Cx::for_testing();
    let send_config = high_repair_config();
    let recv_config = decode_greedy_config();
    let object_id = ObjectId::new(0, 17);
    let data = make_data(DATA_LEN, 0x44);

    let (outcome, symbols) = send_collect(&cx, &send_config, object_id, &data);
    assert!(
        outcome.repair_symbols > 0,
        "erasure test requires repair symbols to recover with"
    );
    assert!(
        symbols.len() > outcome.source_symbols,
        "wire stream carries source + repair"
    );

    let params = params_for(object_id, data.len(), outcome.source_symbols);
    // Drop the first (source) symbol; keep source[1..K] + all repair. The
    // surviving source set alone (K-1) is below K and cannot decode — repair is
    // mandatory.
    let reduced: Vec<AuthenticatedSymbol> = symbols.into_iter().skip(1).collect();
    assert!(
        reduced.len() >= outcome.source_symbols,
        "survivors still clear the K threshold"
    );

    let recv =
        receive(&cx, &recv_config, &params, reduced).expect("repair recovers dropped source");

    assert_eq!(
        &recv.data[..data.len()],
        &data[..],
        "missing source symbol reconstructed from repair"
    );
    assert!(recv.symbols_received >= outcome.source_symbols);
}

#[test]
fn receive_object_with_insufficient_symbols_fails_closed() {
    // Fewer than K symbols can never decode: the receiver must fail closed with
    // InsufficientSymbols rather than panic or return wrong bytes.
    let cx = Cx::for_testing();
    let config = default_config();
    let object_id = ObjectId::new(0, 21);
    let data = make_data(DATA_LEN, 0x55);

    let (outcome, mut symbols) = send_collect(&cx, &config, object_id, &data);
    assert!(outcome.source_symbols >= 2, "need K >= 2 to under-supply");
    let params = params_for(object_id, data.len(), outcome.source_symbols);
    // One short of K source symbols, no repair.
    symbols.truncate(outcome.source_symbols - 1);

    let err = receive(&cx, &config, &params, symbols).expect_err("under-supplied set must fail");
    assert_eq!(
        err.kind(),
        ErrorKind::InsufficientSymbols,
        "fail-closed with the decode-side insufficiency kind"
    );
}

#[test]
fn receive_object_skips_foreign_object_symbols() {
    // The receiver demuxes on params.object_id: symbols for other objects are
    // skipped, and the target object still decodes to its own (distinct) bytes.
    let cx = Cx::for_testing();
    let config = default_config();

    let target_id = ObjectId::new(0, 31);
    let foreign_id = ObjectId::new(0, 99);
    let target_data = make_data(DATA_LEN, 0x66);
    let foreign_data = make_data(DATA_LEN, 0x77);
    assert_ne!(
        target_data, foreign_data,
        "payloads must differ to discriminate"
    );

    let (target_outcome, target_symbols) = send_collect(&cx, &config, target_id, &target_data);
    let (_foreign_outcome, foreign_symbols) = send_collect(&cx, &config, foreign_id, &foreign_data);

    let params = params_for(target_id, target_data.len(), target_outcome.source_symbols);
    // Foreign symbols first so every one is encountered (and skipped) before the
    // target symbols complete the decode.
    let mut mixed = foreign_symbols;
    mixed.extend(target_symbols);

    let recv = receive(&cx, &config, &params, mixed).expect("target decodes amid foreign symbols");

    assert_eq!(
        &recv.data[..target_data.len()],
        &target_data[..],
        "decoded the TARGET object, not the foreign one"
    );
    assert_ne!(
        &recv.data[..foreign_data.len()],
        &foreign_data[..],
        "foreign payload was not the decode result"
    );
    assert!(recv.symbols_received >= target_outcome.source_symbols);
}

#[test]
fn receive_object_reports_unauthenticated_posture() {
    // With no security context and no config-derived auth material, the sender
    // tags symbols with the all-zero sentinel (new_verified(_, zero) ⇒
    // verified=false). The receiver cannot verify them, so ReceiveOutcome must
    // report the symbols as the unauthenticated sentinel and authenticated=false.
    let cx = Cx::for_testing();
    let config = default_config();
    let object_id = ObjectId::new(0, 41);
    let data = make_data(DATA_LEN, 0x88);

    let (outcome, symbols) = send_collect(&cx, &config, object_id, &data);
    let params = params_for(object_id, data.len(), outcome.source_symbols);

    let recv = receive(&cx, &config, &params, symbols).expect("decode");

    assert!(recv.symbols_received > 0);
    assert!(!recv.authenticated, "no auth material ⇒ not authenticated");

    let auth = recv.authentication;
    assert_eq!(auth.verified, 0, "nothing was cryptographically verified");
    assert_eq!(auth.unverified_tagged, 0, "no non-zero tags were carried");
    assert_eq!(
        auth.unauthenticated_sentinel, recv.symbols_received,
        "every consumed symbol carried the zero sentinel"
    );
    assert_eq!(auth.total(), recv.symbols_received);
    assert!(auth.has_unauthenticated_sentinel());
    assert!(!auth.has_unverified_tagged());
    assert!(auth.has_unverified_symbols());
    assert!(!auth.all_verified());

    // ReceiveOutcome predicates agree with the summary on the live path.
    assert!(!recv.all_symbols_verified());
    assert!(recv.has_unverified_symbols());
}

#[test]
fn roundtrip_is_deterministic_across_independent_senders() {
    // Two independent senders with identical inputs emit byte-identical symbol
    // streams and identical SendOutcome accounting; both decode to the original.
    let cx = Cx::for_testing();
    let config = default_config();
    let object_id = ObjectId::new(0, 51);
    let data = make_data(DATA_LEN, 0x99);

    let (outcome_a, symbols_a) = send_collect(&cx, &config, object_id, &data);
    let (outcome_b, symbols_b) = send_collect(&cx, &config, object_id, &data);

    assert_eq!(outcome_a.source_symbols, outcome_b.source_symbols);
    assert_eq!(outcome_a.repair_symbols, outcome_b.repair_symbols);
    assert_eq!(outcome_a.symbols_sent, outcome_b.symbols_sent);
    assert_eq!(
        symbols_a, symbols_b,
        "deterministic encode ⇒ identical streams"
    );

    let params = params_for(object_id, data.len(), outcome_a.source_symbols);
    let recv_a = receive(&cx, &config, &params, symbols_a).expect("decode a");
    let recv_b = receive(&cx, &config, &params, symbols_b).expect("decode b");

    assert_eq!(recv_a.data, recv_b.data, "deterministic decode");
    assert_eq!(&recv_a.data[..data.len()], &data[..]);
}
