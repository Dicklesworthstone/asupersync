//! Per-symbol authentication for the erasure channel
//! (`asupersync-raptorq-leverage-3bb2pl.1`, AC3: Byzantine-injection resistance).
//!
//! Proves the authenticated symbol path end to end over the public
//! `channel::erasure` surface: a sender signs every symbol with a
//! [`SecurityContext`]; a receiver holding the same key authenticates each
//! symbol before it contributes to the decode. An authentic transfer
//! reconstructs byte-identically (even after losing symbols within the repair
//! budget); a receiver with the wrong key authenticates nothing and fails
//! closed — a forged/wrong-key peer cannot inject decoded data.
#![allow(missing_docs)]

use asupersync::channel::erasure::{EcConfig, decode_message_authenticated};
use asupersync::security::SecurityContext;

fn config() -> EcConfig {
    EcConfig {
        symbol_size: 64,
        repair_overhead: 6,
        max_message_size: 1 << 20,
    }
}

#[test]
fn authenticated_roundtrip_is_byte_identical() {
    let cfg = config();
    let ctx = SecurityContext::for_testing(1234);
    let message: Vec<u8> = (0..900u32)
        .map(|i| (i.wrapping_mul(7).wrapping_add(1)) as u8)
        .collect();

    let (header, symbols) = cfg
        .encode_message_authenticated(42, &message, &ctx)
        .expect("authenticated encode");
    assert!(header.total_symbols > header.source_symbols);

    let decoded =
        decode_message_authenticated(&header, &symbols, &ctx).expect("authenticated decode");
    assert_eq!(decoded, message, "authentic transfer must decode exactly");
}

#[test]
fn wrong_key_receiver_fails_closed() {
    let cfg = config();
    let signer = SecurityContext::for_testing(1);
    let wrong_key = SecurityContext::for_testing(2); // a different key
    let message: Vec<u8> = (0..600u32).map(|i| i as u8).collect();

    let (header, symbols) = cfg
        .encode_message_authenticated(7, &message, &signer)
        .expect("encode");

    // Same symbols, but the receiver holds the WRONG key: every symbol fails
    // authentication, so nothing may contribute to the decode — fail closed,
    // never return forged bytes.
    let result = decode_message_authenticated(&header, &symbols, &wrong_key);
    assert!(
        result.is_err(),
        "a wrong-key receiver must fail closed, got {result:?}"
    );
}

#[test]
fn authenticated_recovers_after_loss_within_repair() {
    // Authentication and erasure coding compose: drop two authentic symbols
    // (within the repair budget of 6); the survivors still authenticate and the
    // message still decodes byte-identically.
    let cfg = config();
    let ctx = SecurityContext::for_testing(9);
    let message: Vec<u8> = (0..1200u32).map(|i| (i.wrapping_mul(31)) as u8).collect();

    let (header, mut symbols) = cfg
        .encode_message_authenticated(3, &message, &ctx)
        .expect("encode");
    symbols.remove(4);
    symbols.remove(0);

    let decoded = decode_message_authenticated(&header, &symbols, &ctx)
        .expect("authentic survivors must decode within margin");
    assert_eq!(decoded, message);
}
