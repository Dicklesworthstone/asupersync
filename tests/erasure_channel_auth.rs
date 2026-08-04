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

use asupersync::channel::erasure::{
    AuthenticatedMessageHeader, EcConfig, EcError, MessageHeader, decode_message_authenticated,
};
use asupersync::security::{AuthenticationTag, SecurityContext};

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
    assert!(header.header.total_symbols > header.header.source_symbols);

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

#[test]
fn authenticated_empty_roundtrip_is_canonical_and_key_bound() {
    let cfg = config();
    let signer = SecurityContext::for_testing(31);
    let wrong_key = SecurityContext::for_testing(32);
    let (header, symbols) = cfg
        .encode_message_authenticated(88, &[], &signer)
        .expect("encode empty message");

    assert_eq!(header.header.message_size, 0);
    assert_eq!(header.header.source_symbols, 1);
    assert_eq!(header.header.total_symbols, 1 + cfg.repair_overhead);
    assert!(symbols.is_empty(), "empty payload needs no data symbols");
    assert_eq!(
        decode_message_authenticated(&header, &symbols, &signer).expect("decode empty message"),
        Vec::<u8>::new()
    );
    assert_eq!(
        decode_message_authenticated(&header, &[], &wrong_key),
        Err(EcError::AuthenticationFailed),
        "wrong key must fail before the empty-message shortcut"
    );
}

#[test]
fn zero_size_and_same_k_truncation_forgeries_fail_closed() {
    let cfg = config();
    let ctx = SecurityContext::for_testing(41);
    let message = vec![0xA5; 900];
    let (header, symbols) = cfg
        .encode_message_authenticated(91, &message, &ctx)
        .expect("encode");

    let mut zero_size = header;
    zero_size.header.message_size = 0;
    zero_size.header.source_symbols = 1;
    assert_eq!(
        decode_message_authenticated(&zero_size, &[], &ctx),
        Err(EcError::AuthenticationFailed)
    );

    let mut truncated = header;
    truncated.header.message_size -= 1;
    assert_eq!(
        truncated.header.source_symbols, header.header.source_symbols,
        "mutation stays in the same K bucket"
    );
    assert_eq!(
        decode_message_authenticated(&truncated, &symbols, &ctx),
        Err(EcError::AuthenticationFailed)
    );
}

#[test]
fn every_header_binding_field_and_tag_rejects_mutation() {
    let cfg = config();
    let ctx = SecurityContext::for_testing(51);
    let message = vec![0x3C; 900];
    let (header, symbols) = cfg
        .encode_message_authenticated(101, &message, &ctx)
        .expect("encode");

    let mut mutations = Vec::new();
    let mut changed = header;
    changed.header.message_id ^= 1;
    mutations.push(changed);
    let mut changed = header;
    changed.header.message_size -= 1;
    mutations.push(changed);
    let mut changed = header;
    changed.header.symbol_size += 1;
    mutations.push(changed);
    let mut changed = header;
    changed.header.source_symbols += 1;
    mutations.push(changed);
    let mut changed = header;
    changed.header.total_symbols += 1;
    mutations.push(changed);
    let mut changed = header;
    changed.transfer_digest[0] ^= 1;
    mutations.push(changed);
    let mut changed = header;
    changed.authentication_tag = AuthenticationTag::zero();
    mutations.push(changed);

    for mutated in mutations {
        assert!(
            decode_message_authenticated(&mutated, &symbols, &ctx).is_err(),
            "every authenticated-envelope field must fail closed on mutation"
        );
    }
}

#[test]
fn same_id_and_geometry_cannot_mix_authenticated_transfers() {
    let cfg = config();
    let ctx = SecurityContext::for_testing(61);
    let left = vec![0x11; 900];
    let right = vec![0x22; 900];
    let (left_header, left_symbols) = cfg
        .encode_message_authenticated(111, &left, &ctx)
        .expect("encode left");
    let (right_header, right_symbols) = cfg
        .encode_message_authenticated(111, &right, &ctx)
        .expect("encode right");

    assert_eq!(left_header.header, right_header.header);
    assert_ne!(left_header.transfer_digest, right_header.transfer_digest);
    assert!(decode_message_authenticated(&left_header, &right_symbols, &ctx).is_err());
    assert!(decode_message_authenticated(&right_header, &left_symbols, &ctx).is_err());
}

#[test]
fn authenticated_header_wire_roundtrip_preserves_verifiable_binding() {
    let cfg = config();
    let ctx = SecurityContext::for_testing(71);
    let message = vec![0x7E; 257];
    let (header, symbols) = cfg
        .encode_message_authenticated(121, &message, &ctx)
        .expect("encode");
    let decoded_header =
        AuthenticatedMessageHeader::decode(&header.encode()).expect("decode header envelope");

    assert_eq!(decoded_header, header);
    assert_eq!(
        decode_message_authenticated(&decoded_header, &symbols, &ctx).expect("decode message"),
        message
    );
}

#[test]
fn decoded_message_headers_reject_impossible_geometry() {
    let valid = MessageHeader {
        message_id: 1,
        message_size: 65,
        symbol_size: 64,
        source_symbols: 2,
        total_symbols: 3,
    };

    let mut cases = Vec::new();
    let mut bytes = valid.encode();
    bytes[12..14].copy_from_slice(&0u16.to_le_bytes());
    cases.push(bytes);
    let mut bytes = valid.encode();
    bytes[14..16].copy_from_slice(&0u16.to_le_bytes());
    cases.push(bytes);
    let mut bytes = valid.encode();
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
    cases.push(bytes);
    let mut bytes = valid.encode();
    bytes[14..16].copy_from_slice(&3u16.to_le_bytes());
    cases.push(bytes);

    for bytes in cases {
        assert!(matches!(
            MessageHeader::decode(&bytes),
            Err(EcError::InvalidHeader { .. })
        ));
    }
}
