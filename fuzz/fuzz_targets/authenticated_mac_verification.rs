#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::{
    AUTH_KEY_SIZE, AuthKey, AuthMode, AuthenticatedSymbol, AuthenticationTag, SecurityContext,
};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::Ordering;

const MAX_PAYLOAD_LEN: usize = 1024;

#[derive(Debug, Arbitrary)]
struct AuthenticatedMacInput {
    signing_key: [u8; AUTH_KEY_SIZE],
    alternate_key: [u8; AUTH_KEY_SIZE],
    object_id: u128,
    sbn: u8,
    esi: u32,
    kind: FuzzSymbolKind,
    payload: Vec<u8>,
    tamper: Tamper,
    verifier: VerifierKey,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzSymbolKind {
    Source,
    Repair,
}

impl FuzzSymbolKind {
    fn into_symbol_kind(self) -> SymbolKind {
        match self {
            Self::Source => SymbolKind::Source,
            Self::Repair => SymbolKind::Repair,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum VerifierKey {
    SigningKey,
    AlternateKey,
}

#[derive(Debug, Arbitrary)]
enum Tamper {
    None,
    FlipTagBit {
        bit: u16,
    },
    ZeroSuffix {
        bytes: u8,
    },
    PrefixMix {
        prefix_len: u8,
        other_object_id: u128,
        other_sbn: u8,
        other_esi: u32,
        other_kind: FuzzSymbolKind,
        other_payload: Vec<u8>,
    },
    MutatePayload {
        byte_index: u16,
        new_value: u8,
    },
    MutateObjectId {
        xor_mask: u128,
    },
    MutateSbn {
        delta: u8,
    },
    MutateEsi {
        delta: u32,
    },
    ToggleKind,
}

fuzz_target!(|input: AuthenticatedMacInput| {
    let signing_key = AuthKey::from_bytes(input.signing_key);
    let alternate_key = AuthKey::from_bytes(input.alternate_key);
    let symbol = build_symbol(
        input.object_id,
        input.sbn,
        input.esi,
        input.kind,
        &input.payload,
    );

    let signed = SecurityContext::new(signing_key).sign_symbol(&symbol);
    assert!(
        signed.is_verified(),
        "sign_symbol must produce a verified wrapper"
    );

    let (candidate_symbol, candidate_tag) = apply_tamper(&input.tamper, signing_key, &symbol);
    let verifier_key = match input.verifier {
        VerifierKey::SigningKey => signing_key,
        VerifierKey::AlternateKey => alternate_key,
    };

    let expected_valid = candidate_tag.verify(&verifier_key, &candidate_symbol);
    let recomputed = AuthenticationTag::compute(&verifier_key, &candidate_symbol);
    assert_eq!(
        expected_valid,
        recomputed == candidate_tag,
        "verify() must agree with compute()==candidate_tag for the same verifier key and symbol",
    );

    assert_strict_contract(
        expected_valid,
        verifier_key,
        &candidate_symbol,
        candidate_tag,
    );
    assert_permissive_contract(
        expected_valid,
        verifier_key,
        &candidate_symbol,
        candidate_tag,
    );
    assert_disabled_contract(verifier_key, &candidate_symbol, candidate_tag);
});

fn build_symbol(
    object_id: u128,
    sbn: u8,
    esi: u32,
    kind: FuzzSymbolKind,
    payload: &[u8],
) -> Symbol {
    let payload = payload[..payload.len().min(MAX_PAYLOAD_LEN)].to_vec();
    let symbol_id = SymbolId::new(ObjectId::from_u128(object_id), sbn, esi);
    Symbol::new(symbol_id, payload, kind.into_symbol_kind())
}

fn apply_tamper(
    tamper: &Tamper,
    signing_key: AuthKey,
    symbol: &Symbol,
) -> (Symbol, AuthenticationTag) {
    let base_tag = AuthenticationTag::compute(&signing_key, symbol);
    match tamper {
        Tamper::None => (symbol.clone(), base_tag),
        Tamper::FlipTagBit { bit } => {
            let mut bytes = *base_tag.as_bytes();
            let bit = *bit as usize;
            let byte_index = (bit / 8) % bytes.len();
            let mask = 1u8 << ((bit % 8) as u8);
            bytes[byte_index] ^= mask;
            (symbol.clone(), AuthenticationTag::from_bytes(bytes))
        }
        Tamper::ZeroSuffix { bytes } => {
            let mut mutated = *base_tag.as_bytes();
            let suffix_len = usize::from(*bytes).clamp(1, mutated.len());
            let split = mutated.len() - suffix_len;
            mutated[split..].fill(0);
            (symbol.clone(), AuthenticationTag::from_bytes(mutated))
        }
        Tamper::PrefixMix {
            prefix_len,
            other_object_id,
            other_sbn,
            other_esi,
            other_kind,
            other_payload,
        } => {
            let other_symbol = build_symbol(
                *other_object_id,
                *other_sbn,
                *other_esi,
                *other_kind,
                other_payload,
            );
            let other_tag = AuthenticationTag::compute(&signing_key, &other_symbol);
            let prefix_len = usize::from(*prefix_len) % base_tag.as_bytes().len();
            let mut mixed = *other_tag.as_bytes();
            mixed[..prefix_len].copy_from_slice(&base_tag.as_bytes()[..prefix_len]);
            if mixed == *base_tag.as_bytes() {
                mixed[mixed.len() - 1] ^= 1;
            }
            (symbol.clone(), AuthenticationTag::from_bytes(mixed))
        }
        Tamper::MutatePayload {
            byte_index,
            new_value,
        } => {
            let mut payload = symbol.data().to_vec();
            if payload.is_empty() {
                payload.push(*new_value);
            } else {
                let idx = usize::from(*byte_index) % payload.len();
                let replacement = if payload[idx] == *new_value {
                    new_value.wrapping_add(1)
                } else {
                    *new_value
                };
                payload[idx] = replacement;
            }
            let mutated = Symbol::new(symbol.id(), payload, symbol.kind());
            (mutated, base_tag)
        }
        Tamper::MutateObjectId { xor_mask } => {
            let mask = if *xor_mask == 0 { 1 } else { *xor_mask };
            let mutated_id = SymbolId::new(
                ObjectId::from_u128(symbol.id().object_id().as_u128() ^ mask),
                symbol.sbn(),
                symbol.esi(),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            (mutated, base_tag)
        }
        Tamper::MutateSbn { delta } => {
            let delta = if *delta == 0 { 1 } else { *delta };
            let mutated_id = SymbolId::new(
                symbol.id().object_id(),
                symbol.sbn().wrapping_add(delta),
                symbol.esi(),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            (mutated, base_tag)
        }
        Tamper::MutateEsi { delta } => {
            let delta = if *delta == 0 { 1 } else { *delta };
            let mutated_id = SymbolId::new(
                symbol.id().object_id(),
                symbol.sbn(),
                symbol.esi().wrapping_add(delta),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            (mutated, base_tag)
        }
        Tamper::ToggleKind => {
            let toggled = match symbol.kind() {
                SymbolKind::Source => SymbolKind::Repair,
                SymbolKind::Repair => SymbolKind::Source,
            };
            let mutated = Symbol::new(symbol.id(), symbol.data().to_vec(), toggled);
            (mutated, base_tag)
        }
    }
}

fn assert_strict_contract(
    expected_valid: bool,
    verifier_key: AuthKey,
    symbol: &Symbol,
    tag: AuthenticationTag,
) {
    let ctx = SecurityContext::new(verifier_key).with_mode(AuthMode::Strict);

    let mut received = AuthenticatedSymbol::from_parts(symbol.clone(), tag);
    let result = ctx.verify_authenticated_symbol(&mut received);
    assert_result_matches(result, expected_valid);
    assert_eq!(
        received.is_verified(),
        expected_valid,
        "strict mode must set verified to the verification result",
    );

    let mut preverified = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    let result = ctx.verify_authenticated_symbol(&mut preverified);
    assert_result_matches(result, expected_valid);
    assert_eq!(
        preverified.is_verified(),
        expected_valid,
        "strict mode must clear stale trusted state on failure and preserve it on success",
    );

    let repeat = ctx.verify_authenticated_symbol(&mut preverified);
    assert_result_matches(repeat, expected_valid);
    assert_eq!(
        preverified.is_verified(),
        expected_valid,
        "repeated strict verification must be replay-stable",
    );

    assert_eq!(
        ctx.stats().verified_ok.load(Ordering::Relaxed),
        if expected_valid { 3 } else { 0 },
    );
    assert_eq!(
        ctx.stats().verified_fail.load(Ordering::Relaxed),
        if expected_valid { 0 } else { 3 },
    );
    assert_eq!(ctx.stats().failures_allowed.load(Ordering::Relaxed), 0);
    assert_eq!(ctx.stats().skipped.load(Ordering::Relaxed), 0);
}

fn assert_permissive_contract(
    expected_valid: bool,
    verifier_key: AuthKey,
    symbol: &Symbol,
    tag: AuthenticationTag,
) {
    let ctx = SecurityContext::new(verifier_key).with_mode(AuthMode::Permissive);

    let mut received = AuthenticatedSymbol::from_parts(symbol.clone(), tag);
    let result = ctx.verify_authenticated_symbol(&mut received);
    assert!(result.is_ok(), "permissive mode must not return Err");
    assert_eq!(
        received.is_verified(),
        expected_valid,
        "permissive mode must still reflect the MAC verdict in verified state",
    );

    let mut preverified = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    let result = ctx.verify_authenticated_symbol(&mut preverified);
    assert!(result.is_ok(), "permissive mode must not return Err");
    assert_eq!(
        preverified.is_verified(),
        expected_valid,
        "permissive mode must clear stale trusted state on failure",
    );

    assert_eq!(
        ctx.stats().verified_ok.load(Ordering::Relaxed),
        if expected_valid { 2 } else { 0 },
    );
    assert_eq!(
        ctx.stats().verified_fail.load(Ordering::Relaxed),
        if expected_valid { 0 } else { 2 },
    );
    assert_eq!(
        ctx.stats().failures_allowed.load(Ordering::Relaxed),
        if expected_valid { 0 } else { 2 },
    );
    assert_eq!(ctx.stats().skipped.load(Ordering::Relaxed), 0);
}

fn assert_disabled_contract(verifier_key: AuthKey, symbol: &Symbol, tag: AuthenticationTag) {
    let ctx = SecurityContext::new(verifier_key).with_mode(AuthMode::Disabled);

    let mut received = AuthenticatedSymbol::from_parts(symbol.clone(), tag);
    let result = ctx.verify_authenticated_symbol(&mut received);
    assert!(result.is_ok(), "disabled mode must never return Err");
    assert!(
        !received.is_verified(),
        "disabled mode must leave an unverified wrapper untouched",
    );

    let mut preverified = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    let result = ctx.verify_authenticated_symbol(&mut preverified);
    assert!(result.is_ok(), "disabled mode must never return Err");
    assert!(
        preverified.is_verified(),
        "disabled mode must preserve existing verified state without re-evaluating the MAC",
    );

    assert_eq!(ctx.stats().skipped.load(Ordering::Relaxed), 2);
    assert_eq!(ctx.stats().verified_ok.load(Ordering::Relaxed), 0);
    assert_eq!(ctx.stats().verified_fail.load(Ordering::Relaxed), 0);
    assert_eq!(ctx.stats().failures_allowed.load(Ordering::Relaxed), 0);
}

fn assert_result_matches(
    result: Result<(), asupersync::security::AuthError>,
    expected_valid: bool,
) {
    if expected_valid {
        assert!(result.is_ok(), "valid MAC should verify successfully");
    } else {
        let err = result.expect_err("invalid MAC must fail in strict mode");
        assert!(
            err.is_invalid_tag(),
            "strict-mode failures must surface InvalidTag, got {err:?}",
        );
    }
}
