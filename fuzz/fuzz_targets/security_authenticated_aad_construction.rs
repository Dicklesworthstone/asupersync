#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD_LEN: usize = 1024;
const MAX_SUFFIX_LEN: usize = 64;

#[derive(Debug, Arbitrary)]
struct AuthenticatedAadInput {
    key_bytes: [u8; 32],
    object_id: u128,
    sbn: u8,
    esi: u32,
    kind: FuzzSymbolKind,
    payload: Vec<u8>,
    mutation: AadMutation,
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

#[derive(Debug, Arbitrary)]
enum AadMutation {
    Identical,
    ClonePayload,
    ToggleKind,
    XorObjectId { mask: u128 },
    AdjustSbn { delta: u8 },
    AdjustEsi { delta: u32 },
    OverwritePayloadByte { index: u16, value: u8 },
    TruncatePayload { new_len: u16 },
    AppendSuffix { suffix: Vec<u8> },
    SwapPayloadHalves,
}

fuzz_target!(|input: AuthenticatedAadInput| {
    let key = match AuthKey::from_bytes(input.key_bytes) {
        Ok(key) => key,
        Err(_) => return,
    };

    let ctx = SecurityContext::new(key.clone());
    let base_symbol = build_symbol(
        input.object_id,
        input.sbn,
        input.esi,
        input.kind,
        &input.payload,
    );
    let signed = ctx.sign_symbol(&base_symbol);
    let base_tag = *signed.tag();
    let base_tag_recomputed = AuthenticationTag::compute(&key, &base_symbol);

    assert!(
        signed.is_verified(),
        "sign_symbol must produce a verified wrapper"
    );
    assert_eq!(
        base_tag, base_tag_recomputed,
        "AuthenticationTag::compute must match SecurityContext::sign_symbol",
    );
    assert!(
        base_tag.verify(&key, &base_symbol),
        "freshly signed symbol must verify against its source key",
    );

    let same_symbol_resigned = ctx.sign_symbol(&base_symbol);
    assert_eq!(
        base_tag,
        *same_symbol_resigned.tag(),
        "canonical AAD construction must be deterministic for identical tuples",
    );

    let mutated_symbol = apply_mutation(&base_symbol, &input.mutation);
    let same_canonical_tuple = same_canonical_tuple(&base_symbol, &mutated_symbol);
    let mutated_tag = AuthenticationTag::compute(&key, &mutated_symbol);
    let mut received = AuthenticatedSymbol::from_parts(mutated_symbol.clone(), base_tag);
    let verify_result = ctx.verify_authenticated_symbol(&mut received);

    if same_canonical_tuple {
        assert!(
            verify_result.is_ok(),
            "equal canonical tuples must verify with the original tag",
        );
        assert!(
            received.is_verified(),
            "equal canonical tuples must be marked verified after verification",
        );
        assert_eq!(
            base_tag, mutated_tag,
            "equal canonical tuples must yield identical tags",
        );
    } else {
        assert!(
            verify_result.is_err(),
            "changing any AAD-bound field must invalidate the original tag",
        );
        assert!(
            !received.is_verified(),
            "failed verification must leave the received symbol unverified",
        );

        let resigned = ctx.sign_symbol(&mutated_symbol);
        assert!(
            resigned.is_verified(),
            "signing the mutated symbol must still produce a verified wrapper",
        );
        assert_eq!(
            *resigned.tag(),
            mutated_tag,
            "mutated-symbol signing must agree with AuthenticationTag::compute",
        );
    }
});

fn build_symbol(
    object_id: u128,
    sbn: u8,
    esi: u32,
    kind: FuzzSymbolKind,
    payload: &[u8],
) -> Symbol {
    let symbol_id = SymbolId::new(ObjectId::from_u128(object_id), sbn, esi);
    let payload = payload[..payload.len().min(MAX_PAYLOAD_LEN)].to_vec();
    Symbol::new(symbol_id, payload, kind.into_symbol_kind())
}

fn apply_mutation(symbol: &Symbol, mutation: &AadMutation) -> Symbol {
    match mutation {
        AadMutation::Identical => symbol.clone(),
        AadMutation::ClonePayload => {
            Symbol::new(symbol.id(), symbol.data().to_vec(), symbol.kind())
        }
        AadMutation::ToggleKind => {
            let toggled_kind = match symbol.kind() {
                SymbolKind::Source => SymbolKind::Repair,
                SymbolKind::Repair => SymbolKind::Source,
            };
            Symbol::new(symbol.id(), symbol.data().to_vec(), toggled_kind)
        }
        AadMutation::XorObjectId { mask } => {
            let mask = if *mask == 0 { 1 } else { *mask };
            let symbol_id = SymbolId::new(
                ObjectId::from_u128(symbol.id().object_id().as_u128() ^ mask),
                symbol.sbn(),
                symbol.esi(),
            );
            Symbol::new(symbol_id, symbol.data().to_vec(), symbol.kind())
        }
        AadMutation::AdjustSbn { delta } => {
            let delta = if *delta == 0 { 1 } else { *delta };
            let symbol_id = SymbolId::new(
                symbol.id().object_id(),
                symbol.sbn().wrapping_add(delta),
                symbol.esi(),
            );
            Symbol::new(symbol_id, symbol.data().to_vec(), symbol.kind())
        }
        AadMutation::AdjustEsi { delta } => {
            let delta = if *delta == 0 { 1 } else { *delta };
            let symbol_id = SymbolId::new(
                symbol.id().object_id(),
                symbol.sbn(),
                symbol.esi().wrapping_add(delta),
            );
            Symbol::new(symbol_id, symbol.data().to_vec(), symbol.kind())
        }
        AadMutation::OverwritePayloadByte { index, value } => {
            let mut payload = symbol.data().to_vec();
            if payload.is_empty() {
                payload.push(*value);
            } else {
                let index = usize::from(*index) % payload.len();
                payload[index] = if payload[index] == *value {
                    value.wrapping_add(1)
                } else {
                    *value
                };
            }
            Symbol::new(symbol.id(), payload, symbol.kind())
        }
        AadMutation::TruncatePayload { new_len } => {
            let new_len = usize::from(*new_len).min(symbol.data().len());
            Symbol::new(
                symbol.id(),
                symbol.data()[..new_len].to_vec(),
                symbol.kind(),
            )
        }
        AadMutation::AppendSuffix { suffix } => {
            let mut payload = symbol.data().to_vec();
            let suffix_len = suffix.len().min(MAX_SUFFIX_LEN);
            payload.extend_from_slice(&suffix[..suffix_len]);
            Symbol::new(symbol.id(), payload, symbol.kind())
        }
        AadMutation::SwapPayloadHalves => {
            let payload = symbol.data();
            let split = payload.len() / 2;
            let mut swapped = payload[split..].to_vec();
            swapped.extend_from_slice(&payload[..split]);
            Symbol::new(symbol.id(), swapped, symbol.kind())
        }
    }
}

fn same_canonical_tuple(lhs: &Symbol, rhs: &Symbol) -> bool {
    lhs.id().object_id() == rhs.id().object_id()
        && lhs.sbn() == rhs.sbn()
        && lhs.esi() == rhs.esi()
        && lhs.kind() == rhs.kind()
        && lhs.data() == rhs.data()
}
