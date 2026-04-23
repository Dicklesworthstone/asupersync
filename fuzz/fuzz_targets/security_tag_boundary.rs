//! Byte-level boundary fuzz for AuthenticationTag.
//!
//! The existing `security_tag_verifier`, `authenticated_mac_verification`,
//! and `symbol_auth` targets cover the HMAC verify surface against a
//! reference implementation. They do NOT directly exercise three
//! narrow byte-level contracts that live at the Tag API boundary:
//!
//!   1. `PartialEq` is a correct constant-time byte comparator — any
//!      two tags with byte-equal content compare equal; any one-bit
//!      difference compares unequal (XOR-accumulator at
//!      src/security/tag.rs:94-102).
//!
//!   2. `from_bytes` + `as_bytes` round-trip losslessly for all
//!      32-byte inputs — any `[u8; 32]` survives the Tag wrapper.
//!
//!   3. `AuthenticationTag::zero()` (documented as an invalid sentinel)
//!      MUST NOT verify against any (key, symbol) combination produced
//!      through the normal Symbol API. HMAC-SHA256 colliding with 32
//!      zero bytes is cryptographically negligible; finding one would
//!      be a catastrophic finding.
//!
//! Archetype-5 target: narrowly-scoped crash+invariant on the
//! non-cryptographic API surface. Runs fast (no HMAC on the hot path
//! for the PartialEq/from_bytes cases).

#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::key::{AUTH_KEY_SIZE, AuthKey};
use asupersync::security::tag::{AuthenticationTag, TAG_SIZE};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD: usize = 1024;

#[derive(Arbitrary, Debug)]
enum Case {
    /// PartialEq byte-equality contract.
    ByteEq {
        lhs: [u8; TAG_SIZE],
        diff_bit: u16, // bit index to flip for the inequality check
    },
    /// from_bytes/as_bytes lossless round-trip.
    RoundTrip {
        bytes: [u8; TAG_SIZE],
    },
    /// Zero-tag sentinel never verifies any normal symbol.
    ZeroTagNeverVerifies {
        key_seed: u64,
        object_id: u128,
        sbn: u8,
        esi: u32,
        kind_bit: bool,
        payload: Vec<u8>,
    },
}

fn make_symbol(object_id: u128, sbn: u8, esi: u32, kind_bit: bool, payload: Vec<u8>) -> Symbol {
    let id = SymbolId::new(ObjectId::from_u128(object_id), sbn, esi);
    let kind = if kind_bit { SymbolKind::Source } else { SymbolKind::Repair };
    let payload = if payload.len() > MAX_PAYLOAD {
        payload[..MAX_PAYLOAD].to_vec()
    } else {
        payload
    };
    Symbol::new(id, payload, kind)
}

fuzz_target!(|case: Case| {
    match case {
        Case::ByteEq { lhs, diff_bit } => {
            // (a) Reflexivity: a tag equals itself regardless of byte content.
            let a = AuthenticationTag::from_bytes(lhs);
            let b = AuthenticationTag::from_bytes(lhs);
            assert!(
                a == b,
                "PartialEq: byte-equal tags compared unequal (bytes={lhs:?})",
            );

            // (b) Any single-bit difference must compare unequal.
            let mut rhs_bytes = lhs;
            let bit = (diff_bit as usize) % (TAG_SIZE * 8);
            let byte_idx = bit / 8;
            let mask = 1u8 << (bit % 8);
            rhs_bytes[byte_idx] ^= mask;
            let rhs = AuthenticationTag::from_bytes(rhs_bytes);
            assert!(
                a != rhs,
                "PartialEq: single-bit-diff tags compared equal (bit={bit})",
            );
        }
        Case::RoundTrip { bytes } => {
            let tag = AuthenticationTag::from_bytes(bytes);
            assert_eq!(
                tag.as_bytes(),
                &bytes,
                "from_bytes/as_bytes round-trip lost data",
            );
            // Self-equality via constant-time PartialEq still holds.
            assert!(tag == AuthenticationTag::from_bytes(bytes));
            // zero-tag is equal to from_bytes([0;32]).
            if bytes == [0u8; TAG_SIZE] {
                assert!(tag == AuthenticationTag::zero());
            }
        }
        Case::ZeroTagNeverVerifies {
            key_seed,
            object_id,
            sbn,
            esi,
            kind_bit,
            payload,
        } => {
            let key = AuthKey::from_seed(key_seed);
            let symbol = make_symbol(object_id, sbn, esi, kind_bit, payload);
            let zero = AuthenticationTag::zero();
            // A 32-byte zero string is astronomically unlikely to be the
            // HMAC-SHA256 of anything. If the fuzzer ever hits this, it's
            // either a broken AuthKey/Symbol path or a real cryptographic
            // anomaly — either way, surface it loudly.
            assert!(
                !zero.verify(&key, &symbol),
                "zero-tag sentinel verified a real symbol: key_seed={key_seed}, \
                 object_id={object_id}, sbn={sbn}, esi={esi}, kind_bit={kind_bit}, \
                 payload_len={}",
                symbol.data().len(),
            );
            // Double check: a freshly computed tag over the same symbol must
            // itself verify. Keeps the target honest against a broken
            // Symbol factory that produces verify-always-false states.
            let fresh = AuthenticationTag::compute(&key, &symbol);
            assert!(
                fresh.verify(&key, &symbol),
                "freshly computed tag failed to verify its own symbol — tag factory broken",
            );
        }
    }

    // Keep AUTH_KEY_SIZE referenced so the import is not removed during
    // future refactors; the ZeroTagNeverVerifies arm already uses AuthKey.
    let _ = AUTH_KEY_SIZE;
});
