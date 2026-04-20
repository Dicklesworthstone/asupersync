#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::key::{AUTH_KEY_SIZE, AuthKey};
use asupersync::security::tag::{AuthenticationTag, TAG_SIZE};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use hmac::{Hmac, Mac};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const AUTH_TAG_DOMAIN: &[u8] = b"asupersync::security::AuthenticationTag::v1";
const MAX_PAYLOAD_LEN: usize = 1024;

#[derive(Debug, Arbitrary)]
struct TagVerifierFuzzInput {
    key_bytes: [u8; AUTH_KEY_SIZE],
    object_id: u128,
    sbn: u8,
    esi: u32,
    kind: FuzzSymbolKind,
    payload: Vec<u8>,
    mutation: Mutation,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzSymbolKind {
    Source,
    Repair,
}

#[derive(Debug, Arbitrary)]
enum Mutation {
    None,
    FlipTagBit { bit: u16 },
    WrongKey { byte_index: u8, xor_mask: u8 },
    MutatePayload { byte_index: u16, new_value: u8 },
    MutateObjectId { xor_mask: u128 },
    MutateSbn { delta: u8 },
    MutateEsi { delta: u32 },
    ToggleKind,
    ZeroTag,
}

fuzz_target!(|input: TagVerifierFuzzInput| {
    let symbol = build_symbol(
        input.object_id,
        input.sbn,
        input.esi,
        input.kind,
        &input.payload,
    );
    let key = AuthKey::from_bytes(input.key_bytes);

    let computed = AuthenticationTag::compute(&key, &symbol);
    let reference = reference_tag_bytes(&key, &symbol);
    assert_eq!(
        computed.as_bytes(),
        &reference,
        "AuthenticationTag::compute must match the reference HMAC contract",
    );
    assert!(
        computed.verify(&key, &symbol),
        "freshly computed tag must verify"
    );
    assert!(
        AuthenticationTag::from_bytes(reference).verify(&key, &symbol),
        "reference tag bytes must verify through the public verifier"
    );

    let (candidate_tag, candidate_key, candidate_symbol) =
        apply_mutation(&computed, &key, &symbol, &input.mutation);
    let expected = reference_verify(candidate_tag.as_bytes(), &candidate_key, &candidate_symbol);
    assert_eq!(
        candidate_tag.verify(&candidate_key, &candidate_symbol),
        expected,
        "public verifier diverged from reference HMAC verification"
    );
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
    let kind = match kind {
        FuzzSymbolKind::Source => SymbolKind::Source,
        FuzzSymbolKind::Repair => SymbolKind::Repair,
    };
    Symbol::new(symbol_id, payload, kind)
}

fn apply_mutation(
    computed: &AuthenticationTag,
    key: &AuthKey,
    symbol: &Symbol,
    mutation: &Mutation,
) -> (AuthenticationTag, AuthKey, Symbol) {
    match mutation {
        Mutation::None => (*computed, *key, symbol.clone()),
        Mutation::FlipTagBit { bit } => {
            let mut bytes = *computed.as_bytes();
            let bit = *bit as usize;
            let byte_index = (bit / 8) % TAG_SIZE;
            let mask = 1u8 << ((bit % 8) as u8);
            bytes[byte_index] ^= mask;
            (AuthenticationTag::from_bytes(bytes), *key, symbol.clone())
        }
        Mutation::WrongKey {
            byte_index,
            xor_mask,
        } => {
            let mut key_bytes = *key.as_bytes();
            let idx = (*byte_index as usize) % AUTH_KEY_SIZE;
            let mask = if *xor_mask == 0 { 1 } else { *xor_mask };
            key_bytes[idx] ^= mask;
            (*computed, AuthKey::from_bytes(key_bytes), symbol.clone())
        }
        Mutation::MutatePayload {
            byte_index,
            new_value,
        } => {
            let mut payload = symbol.data().to_vec();
            if payload.is_empty() {
                payload.push(*new_value);
            } else {
                let idx = (*byte_index as usize) % payload.len();
                payload[idx] = *new_value;
            }
            let mutated = Symbol::new(symbol.id(), payload, symbol.kind());
            (*computed, *key, mutated)
        }
        Mutation::MutateObjectId { xor_mask } => {
            let current = symbol.id().object_id().as_u128();
            let mask = if *xor_mask == 0 { 1 } else { *xor_mask };
            let mutated_id = SymbolId::new(
                ObjectId::from_u128(current ^ mask),
                symbol.sbn(),
                symbol.esi(),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            (*computed, *key, mutated)
        }
        Mutation::MutateSbn { delta } => {
            let delta = if *delta == 0 { 1 } else { *delta };
            let mutated_id = SymbolId::new(
                symbol.id().object_id(),
                symbol.sbn().wrapping_add(delta),
                symbol.esi(),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            (*computed, *key, mutated)
        }
        Mutation::MutateEsi { delta } => {
            let delta = if *delta == 0 { 1 } else { *delta };
            let mutated_id = SymbolId::new(
                symbol.id().object_id(),
                symbol.sbn(),
                symbol.esi().wrapping_add(delta),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            (*computed, *key, mutated)
        }
        Mutation::ToggleKind => {
            let kind = match symbol.kind() {
                SymbolKind::Source => SymbolKind::Repair,
                SymbolKind::Repair => SymbolKind::Source,
            };
            let mutated = Symbol::new(symbol.id(), symbol.data().to_vec(), kind);
            (*computed, *key, mutated)
        }
        Mutation::ZeroTag => (AuthenticationTag::zero(), *key, symbol.clone()),
    }
}

fn reference_verify(tag_bytes: &[u8; TAG_SIZE], key: &AuthKey, symbol: &Symbol) -> bool {
    reference_tag_bytes(key, symbol) == *tag_bytes
}

fn reference_tag_bytes(key: &AuthKey, symbol: &Symbol) -> [u8; TAG_SIZE] {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(AUTH_TAG_DOMAIN);
    mac.update(&symbol.id().object_id().as_u128().to_le_bytes());
    mac.update(&[symbol.sbn()]);
    mac.update(&symbol.esi().to_le_bytes());
    mac.update(&[match symbol.kind() {
        SymbolKind::Source => 0x53,
        SymbolKind::Repair => 0xA7,
    }]);
    mac.update(&(symbol.data().len() as u64).to_le_bytes());
    if !symbol.data().is_empty() {
        mac.update(symbol.data());
    }
    mac.finalize().into_bytes().into()
}
