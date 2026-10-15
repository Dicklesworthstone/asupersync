//! RaptorQ pipeline `send_symbols` + `source_mut` conformance (bd-3uox5).
//!
//! VEIN: two public pipeline methods had ZERO references anywhere under
//! `tests/`:
//!   * `RaptorQSender::send_symbols` (src/raptorq/pipeline.rs:242) — the
//!     pre-encoded-replay path. Unlike `send_object` (which encodes), this
//!     accepts an iterator of already-authenticated symbols, checkpoints `cx`
//!     at each boundary, drives the blocking send loop, flushes, and returns
//!     the count delivered. `send_object` is exercised by
//!     raptorq_pipeline_roundtrip_conformance; `send_symbols` was not.
//!   * `RaptorQReceiver::source_mut` (src/raptorq/pipeline.rs:447) — the live,
//!     mutable handle on the receiver's symbol source. The companion
//!     `RaptorQSender::transport_mut` IS used (to read `CollectingSink`), but
//!     `source_mut` had no coverage, so the property that it exposes the SAME
//!     stream the receiver lazily drains was unpinned.
//!
//! These are oracle-free properties on the PUBLIC surface
//! (`RaptorQSenderBuilder` / `RaptorQReceiverBuilder` + the public
//! `transport::sink::CollectingSink` / `transport::stream::VecStream`):
//!   * `send_symbols` is a byte-identical, order-preserving replay of whatever
//!     symbols it is handed (the encoder is NOT re-run), returning an exact
//!     count;
//!   * empty input sends nothing and returns 0;
//!   * successive calls accumulate on the transport in call order, each
//!     reporting only its own batch length;
//!   * the replayed stream still decodes end-to-end through a real receiver;
//!   * a pre-cancelled `Cx` fails the send CLOSED at the first checkpoint with
//!     nothing delivered (`send_symbols` honors cooperative cancellation);
//!   * `source_mut` exposes the full stream before any receive, the residual
//!     after an over-supplied partial consume (proving it is the live object
//!     the receiver pulled from, not a snapshot), and a fully drained stream
//!     when exactly K source symbols are supplied.
//!
//! `Cx::for_testing()` / `set_cancel_requested` are gated behind
//! `cfg(any(test, feature="test-internals"))`, so this crate REQUIRES
//! `--features test-internals`.
//!
//! RCH (additive, new file — no shared-src edits):
//!   RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
//!     RUSTFLAGS='-D warnings' cargo test -p asupersync \
//!     --features test-internals \
//!     --test raptorq_pipeline_send_symbols_source_mut_conformance

use asupersync::config::RaptorQConfig;
use asupersync::cx::Cx;
use asupersync::raptorq::{
    RaptorQReceiverBuilder, RaptorQSender, RaptorQSenderBuilder, SendOutcome,
};
use asupersync::security::AuthenticatedSymbol;
use asupersync::transport::sink::CollectingSink;
use asupersync::transport::stream::{SymbolStream, VecStream};
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

/// Over-provision repair so the wire carries spare symbols past K.
fn high_repair_config() -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = SYMBOL_SIZE;
    config.encoding.repair_overhead = 2.0;
    config
}

/// Decode greedily: `repair_overhead = 1.0` sets the decode-attempt threshold
/// to exactly K, so the receiver decodes as soon as it has K symbols.
fn decode_greedy_config() -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = SYMBOL_SIZE;
    config.encoding.repair_overhead = 1.0;
    config
}

/// Deterministic, byte-varied payload (uniform data would make decode vacuous).
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

/// Build a sender over a fresh `CollectingSink`.
fn new_sender(config: &RaptorQConfig) -> RaptorQSender<CollectingSink> {
    RaptorQSenderBuilder::new()
        .config(config.clone())
        .transport(CollectingSink::new())
        .build()
        .expect("sender build")
}

/// Encode `data` with `send_object` and return the outcome plus every symbol
/// the encoder placed on the wire (source-first, systematic order).
fn encode_symbols(
    cx: &Cx,
    config: &RaptorQConfig,
    object_id: ObjectId,
    data: &[u8],
) -> (SendOutcome, Vec<AuthenticatedSymbol>) {
    let mut sender = new_sender(config);
    let outcome = sender
        .send_object(cx, object_id, data)
        .expect("send_object should succeed");
    let symbols = sender.transport_mut().symbols().to_vec();
    (outcome, symbols)
}

// =========================================================================
// send_symbols
// =========================================================================

#[test]
fn send_symbols_replays_preencoded_symbols_byte_identical_and_returns_count() {
    let cx = Cx::for_testing();
    let object_id = ObjectId::new(0, 1);
    let data = make_data(DATA_LEN, 0x11);

    // Encode once to obtain a concrete, authenticated symbol stream.
    let (_outcome, symbols) = encode_symbols(&cx, &default_config(), object_id, &data);
    assert!(!symbols.is_empty(), "encoder produced symbols");

    // Replay those exact symbols through a FRESH sender (no re-encode).
    let mut replayer = new_sender(&default_config());
    let count = replayer
        .send_symbols(&cx, symbols.clone())
        .expect("send_symbols should succeed");

    assert_eq!(count, symbols.len(), "returns the exact number handed in");
    assert_eq!(
        replayer.transport_mut().symbols(),
        symbols.as_slice(),
        "send_symbols transmits the supplied symbols byte-identically, in order, \
         with no re-encoding"
    );
}

#[test]
fn send_symbols_empty_input_sends_nothing_and_returns_zero() {
    let cx = Cx::for_testing();
    let mut sender = new_sender(&default_config());

    let count = sender
        .send_symbols(&cx, Vec::<AuthenticatedSymbol>::new())
        .expect("empty send_symbols still succeeds (and flushes)");

    assert_eq!(count, 0, "no symbols supplied => count 0");
    assert!(
        sender.transport_mut().symbols().is_empty(),
        "nothing was placed on the transport",
    );
}

#[test]
fn send_symbols_accumulates_across_calls_in_order() {
    let cx = Cx::for_testing();
    let object_id = ObjectId::new(0, 2);
    let data = make_data(DATA_LEN, 0x22);

    let (_outcome, symbols) = encode_symbols(&cx, &default_config(), object_id, &data);
    assert!(symbols.len() >= 2, "need at least two symbols to split");

    let mid = symbols.len() / 2;
    let (head, tail) = symbols.split_at(mid);

    let mut sender = new_sender(&default_config());
    let c1 = sender
        .send_symbols(&cx, head.to_vec())
        .expect("first batch");
    let c2 = sender
        .send_symbols(&cx, tail.to_vec())
        .expect("second batch");

    assert_eq!(c1, head.len(), "first call counts only its own batch");
    assert_eq!(c2, tail.len(), "second call counts only its own batch");
    assert_eq!(
        sender.transport_mut().symbols(),
        symbols.as_slice(),
        "the transport accumulates head ++ tail in call order, reconstructing \
         the original stream",
    );
}

#[test]
fn send_symbols_replayed_stream_decodes_end_to_end() {
    let cx = Cx::for_testing();
    let object_id = ObjectId::new(0, 3);
    let data = make_data(DATA_LEN, 0x33);

    // Encode, then replay through send_symbols over a CollectingSink.
    let (outcome, symbols) = encode_symbols(&cx, &default_config(), object_id, &data);
    let mut replayer = new_sender(&default_config());
    let count = replayer
        .send_symbols(&cx, symbols)
        .expect("replay send_symbols");
    assert_eq!(count, outcome.symbols_sent);

    // Feed the replayed wire bytes to a real receiver: it must reconstruct the
    // original object, proving send_symbols is a faithful e2e transport replay.
    let replayed = replayer.transport_mut().symbols().to_vec();
    let params = params_for(object_id, data.len(), outcome.source_symbols);
    let mut receiver = RaptorQReceiverBuilder::new()
        .config(default_config())
        .source(VecStream::new(replayed))
        .build()
        .expect("receiver build");
    let recv = receiver
        .receive_object(&cx, &params)
        .expect("decode replayed stream");

    assert_eq!(
        &recv.data[..data.len()],
        &data[..],
        "round-trip fidelity through the send_symbols replay path",
    );
}

#[test]
fn send_symbols_fails_closed_on_cancelled_cx() {
    let cx = Cx::for_testing();
    let object_id = ObjectId::new(0, 4);
    let data = make_data(DATA_LEN, 0x44);
    let (_outcome, symbols) = encode_symbols(&cx, &default_config(), object_id, &data);
    assert!(!symbols.is_empty());

    // A second, pre-cancelled context: the very first per-symbol checkpoint
    // must trip before anything is handed to the transport.
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);

    let mut sender = new_sender(&default_config());
    let result = sender.send_symbols(&cancelled, symbols);

    assert!(
        result.is_err(),
        "a cancelled context fails send_symbols closed",
    );
    assert!(
        sender.transport_mut().symbols().is_empty(),
        "no symbol is delivered once cancellation is observed at the first \
         checkpoint",
    );
}

// =========================================================================
// source_mut
// =========================================================================

#[test]
fn source_mut_exposes_full_stream_before_receive() {
    let cx = Cx::for_testing();
    let object_id = ObjectId::new(0, 5);
    let data = make_data(DATA_LEN, 0x55);
    let (_outcome, symbols) = encode_symbols(&cx, &default_config(), object_id, &data);
    let n = symbols.len();

    let mut receiver = RaptorQReceiverBuilder::new()
        .config(default_config())
        .source(VecStream::new(symbols))
        .build()
        .expect("receiver build");

    // Before any receive, source_mut exposes the live source carrying every
    // loaded symbol.
    assert_eq!(
        receiver.source_mut().size_hint(),
        (n, Some(n)),
        "source_mut yields the fully loaded internal stream",
    );
}

#[test]
fn source_mut_exposes_residual_after_partial_consume() {
    let cx = Cx::for_testing();
    let object_id = ObjectId::new(0, 6);
    let data = make_data(DATA_LEN, 0x66);

    // Over-provision repair (overhead 2.0) so the wire carries well past K.
    let (_outcome, symbols) = encode_symbols(&cx, &high_repair_config(), object_id, &data);
    let n = symbols.len();
    let params = params_for(object_id, data.len(), _outcome.source_symbols);

    let mut receiver = RaptorQReceiverBuilder::new()
        // Greedy: decode as soon as K symbols are available, leaving the rest.
        .config(decode_greedy_config())
        .source(VecStream::new(symbols))
        .build()
        .expect("receiver build");

    let recv = receiver
        .receive_object(&cx, &params)
        .expect("over-supplied decode");
    assert_eq!(&recv.data[..data.len()], &data[..], "decode fidelity");

    let (remaining, upper) = receiver.source_mut().size_hint();
    assert_eq!(
        upper,
        Some(remaining),
        "VecStream reports an exact remaining"
    );
    // The receiver pulled lazily and stopped once decode completed.
    assert!(
        remaining > 0,
        "an over-supplied stream still has unconsumed symbols ({remaining} left of {n})",
    );
    assert!(
        remaining < n,
        "the receiver consumed at least the K it needed"
    );
    // Pulled symbols = n - remaining; every accepted symbol was pulled, so the
    // residual can never exceed n minus what was accepted. This binds source_mut
    // to the SAME stream the receiver drained.
    assert!(
        remaining <= n - recv.symbols_received,
        "source_mut reflects live consumption: pulled ({}) >= accepted ({})",
        n - remaining,
        recv.symbols_received,
    );
}

#[test]
fn source_mut_drains_to_zero_when_exactly_k_supplied() {
    let cx = Cx::for_testing();
    let object_id = ObjectId::new(0, 7);
    let data = make_data(DATA_LEN, 0x77);

    let (outcome, mut symbols) = encode_symbols(&cx, &default_config(), object_id, &data);
    // Systematic: the first K symbols are the source symbols; feed exactly K.
    symbols.truncate(outcome.source_symbols);
    let k = symbols.len();
    assert_eq!(k, outcome.source_symbols);
    let params = params_for(object_id, data.len(), outcome.source_symbols);

    let mut receiver = RaptorQReceiverBuilder::new()
        .config(decode_greedy_config())
        .source(VecStream::new(symbols))
        .build()
        .expect("receiver build");

    let recv = receiver
        .receive_object(&cx, &params)
        .expect("exactly-K decode");
    assert_eq!(&recv.data[..data.len()], &data[..], "decode fidelity");
    assert_eq!(recv.symbols_received, k, "all K source symbols consumed");

    assert_eq!(
        receiver.source_mut().size_hint(),
        (0, Some(0)),
        "source_mut exposes a fully drained stream once every symbol was pulled",
    );
}
