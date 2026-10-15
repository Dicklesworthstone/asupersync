//! Async `EcSender`/`EcReceiver` round-trip for the erasure channel
//! (`asupersync-raptorq-leverage-3bb2pl.1`): the channel-shaped composition.
//!
//! Drives the public `channel::erasure::channel()` over its in-memory reliable
//! transport: a sender encodes messages into symbols and flushes them; an async
//! receiver reassembles and decodes them back to the original bytes. Reactor-free
//! (`futures_lite::block_on` over the cancel-aware unbounded symbol transport),
//! so it needs no platform runtime — only the `test-internals` `Cx::for_testing`.
//!
//! Scope: this proves the channel SHAPE (send -> transport -> reassemble ->
//! decode -> recv), multi-message FIFO, cancel-before-flush, and transport-close
//! fail-closed over a loss-free transport. Lossy-transport delivery is proven at
//! the symbol layer (loss-matrix + decode round-trip suites); wiring a seeded
//! `LossModel` into this transport is a sibling slice.
#![allow(missing_docs)]

use asupersync::channel::erasure::{EcConfig, EcError, channel};
use asupersync::cx::Cx;
use futures_lite::future::block_on;

fn config() -> EcConfig {
    EcConfig {
        symbol_size: 64,
        repair_overhead: 6,
        max_message_size: 1 << 20,
    }
}

#[test]
fn async_send_recv_roundtrip_is_byte_identical() {
    let (mut tx, mut rx) = channel(config());
    let cx = Cx::for_testing();
    let message: Vec<u8> = (0..900u32)
        .map(|i| (i.wrapping_mul(97).wrapping_add(5)) as u8)
        .collect();

    let id = tx.send(&cx, &message).expect("send");
    assert_eq!(id, 0, "first message id");

    let got = block_on(rx.recv(&cx)).expect("recv");
    assert_eq!(got, message, "round-trip must be byte-identical");
}

#[test]
fn async_send_recv_scales_symbol_cap_past_8192() {
    const K: usize = 8_193;
    const SYMBOL_SIZE: u16 = 8;
    let message_size = K * usize::from(SYMBOL_SIZE);
    let config = EcConfig {
        symbol_size: SYMBOL_SIZE,
        repair_overhead: 0,
        max_message_size: message_size,
    };
    let (mut tx, mut rx) = channel(config);
    let cx = Cx::for_testing();
    let message: Vec<u8> = (0..message_size).map(|i| i as u8).collect();

    tx.send(&cx, &message).expect("send K=8193 message");
    let decoded = block_on(rx.recv(&cx)).expect("receive K=8193 message");
    assert_eq!(decoded, message);
}

#[test]
fn async_multiple_messages_arrive_in_fifo_order() {
    let (mut tx, mut rx) = channel(config());
    let cx = Cx::for_testing();
    let a: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..500u32).map(|i| (255 - (i % 256)) as u8).collect();
    let c = b"the third message".to_vec();

    assert_eq!(tx.send(&cx, &a).expect("send a"), 0);
    assert_eq!(tx.send(&cx, &b).expect("send b"), 1);
    assert_eq!(tx.send(&cx, &c).expect("send c"), 2);

    assert_eq!(block_on(rx.recv(&cx)).expect("recv a"), a);
    assert_eq!(block_on(rx.recv(&cx)).expect("recv b"), b);
    assert_eq!(block_on(rx.recv(&cx)).expect("recv c"), c);
}

#[test]
fn empty_message_roundtrips() {
    let (mut tx, mut rx) = channel(config());
    let cx = Cx::for_testing();
    tx.send(&cx, &[]).expect("send empty");
    let got = block_on(rx.recv(&cx)).expect("recv empty");
    assert!(got.is_empty(), "an empty message must round-trip to empty");
}

#[test]
fn cancelled_sender_flushes_nothing() {
    let (mut tx, _rx) = channel(config());
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    let result = tx.send(&cx, b"must never leave the sender");
    assert!(
        matches!(result, Err(EcError::Cancelled)),
        "a cancelled sender must fail closed before flushing, got {result:?}"
    );
}

#[test]
fn recv_fails_closed_when_transport_is_closed() {
    let (tx, mut rx) = channel(config());
    drop(tx); // close the transport with no message in flight
    let cx = Cx::for_testing();

    let result = block_on(rx.recv(&cx));
    assert!(
        matches!(result, Err(EcError::TransportClosed)),
        "recv on a closed empty transport must fail closed, got {result:?}"
    );
}
