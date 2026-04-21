#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::{
    AUTH_KEY_SIZE, AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext,
};
use asupersync::types::{Symbol, SymbolId, SymbolKind};
use asupersync::util::DetRng;
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD_LEN: usize = 1024;
const MAX_PURPOSES: usize = 8;
const MAX_PURPOSE_LEN: usize = 128;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    key_source: KeySource,
    primary_chain: Vec<Vec<u8>>,
    alternate_chain: Vec<Vec<u8>>,
    symbol: SymbolInput,
    mutation: Mutation,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum KeySource {
    Seed(u64),
    Raw([u8; AUTH_KEY_SIZE]),
    DeterministicRng(u64),
}

#[derive(Arbitrary, Debug, Clone)]
struct SymbolInput {
    object_id: u64,
    sbn: u8,
    esi: u32,
    kind: SymbolKindInput,
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SymbolKindInput {
    Source,
    Repair,
}

#[derive(Arbitrary, Debug, Clone)]
enum Mutation {
    None,
    FlipTagByte { byte_index: u8, xor_mask: u8 },
    MutatePayload { byte_index: u16, new_value: u8 },
    MutateObjectId { xor_mask: u64 },
    MutateEsi { delta: u32 },
    ToggleKind,
}

impl From<SymbolKindInput> for SymbolKind {
    fn from(kind: SymbolKindInput) -> Self {
        match kind {
            SymbolKindInput::Source => SymbolKind::Source,
            SymbolKindInput::Repair => SymbolKind::Repair,
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz_key_derivation_context(input);
});

fn fuzz_key_derivation_context(input: FuzzInput) {
    let base_key = build_base_key(input.key_source);
    let primary_chain = normalize_chain(input.primary_chain);
    let alternate_chain = normalize_chain(input.alternate_chain);
    let symbol = build_symbol(input.symbol);

    let primary_key = derive_key(base_key, &primary_chain);
    let repeated_primary_key = derive_key(base_key, &primary_chain);
    assert_eq!(
        primary_key, repeated_primary_key,
        "derive_subkey must be deterministic for the same purpose chain"
    );

    let primary_tag = AuthenticationTag::compute(&primary_key, &symbol);
    assert!(
        primary_tag.verify(&primary_key, &symbol),
        "freshly derived key must verify its own tag"
    );

    let primary_ctx = derive_context_chain(SecurityContext::new(base_key), &primary_chain);
    let signed = primary_ctx.sign_symbol(&symbol);
    assert_eq!(
        signed.tag(),
        &primary_tag,
        "SecurityContext::derive_context must match AuthKey::derive_subkey"
    );

    let mut received = AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());
    primary_ctx
        .verify_authenticated_symbol(&mut received)
        .expect("same derived context must verify its own signature");
    assert!(received.is_verified());

    let alternate_key = derive_key(base_key, &alternate_chain);
    let alternate_ctx = derive_context_chain(SecurityContext::new(base_key), &alternate_chain);
    let alternate_tag = AuthenticationTag::compute(&alternate_key, &symbol);
    let alternate_signed = alternate_ctx.sign_symbol(&symbol);
    assert_eq!(
        alternate_signed.tag(),
        &alternate_tag,
        "derived context signing must be deterministic"
    );

    if primary_key != alternate_key && primary_tag != alternate_tag {
        assert!(
            !primary_tag.verify(&alternate_key, &symbol),
            "a tag from one derived key must not verify under a different derived key"
        );

        let mut wrong_context_auth = AuthenticatedSymbol::from_parts(symbol.clone(), primary_tag);
        let wrong_context_result =
            alternate_ctx.verify_authenticated_symbol(&mut wrong_context_auth);
        assert!(wrong_context_result.is_err());
        assert!(!wrong_context_auth.is_verified());
    }

    apply_mutation(&symbol, primary_key, primary_tag, input.mutation);
}

fn build_base_key(source: KeySource) -> AuthKey {
    match source {
        KeySource::Seed(seed) => {
            let key = AuthKey::from_seed(seed);
            assert_eq!(key, AuthKey::from_seed(seed));
            key
        }
        KeySource::Raw(bytes) => {
            let key = AuthKey::from_bytes(bytes);
            assert_eq!(key.as_bytes(), &bytes);
            key
        }
        KeySource::DeterministicRng(seed) => {
            let mut rng_a = DetRng::new(seed);
            let key_a = AuthKey::from_rng(&mut rng_a);
            let mut rng_b = DetRng::new(seed);
            let key_b = AuthKey::from_rng(&mut rng_b);
            assert_eq!(key_a, key_b, "from_rng must be reproducible for DetRng");
            key_a
        }
    }
}

fn normalize_chain(chain: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    chain
        .into_iter()
        .take(MAX_PURPOSES)
        .map(|mut purpose| {
            purpose.truncate(MAX_PURPOSE_LEN);
            purpose
        })
        .collect()
}

fn derive_key(mut key: AuthKey, chain: &[Vec<u8>]) -> AuthKey {
    for purpose in chain {
        key = key.derive_subkey(purpose);
    }
    key
}

fn derive_context_chain(mut context: SecurityContext, chain: &[Vec<u8>]) -> SecurityContext {
    for purpose in chain {
        context = context.derive_context(purpose);
    }
    context
}

fn build_symbol(input: SymbolInput) -> Symbol {
    let mut payload = input.payload;
    payload.truncate(MAX_PAYLOAD_LEN);
    let id = SymbolId::new_for_test(input.object_id, input.sbn, input.esi);
    Symbol::new(id, payload, input.kind.into())
}

fn apply_mutation(symbol: &Symbol, key: AuthKey, tag: AuthenticationTag, mutation: Mutation) {
    match mutation {
        Mutation::None => {}
        Mutation::FlipTagByte {
            byte_index,
            xor_mask,
        } => {
            let mut bytes = *tag.as_bytes();
            let index = usize::from(byte_index) % bytes.len();
            let mask = if xor_mask == 0 { 1 } else { xor_mask };
            bytes[index] ^= mask;
            let mutated_tag = AuthenticationTag::from_bytes(bytes);
            if mutated_tag != tag {
                assert!(!mutated_tag.verify(&key, symbol));
            }
        }
        Mutation::MutatePayload {
            byte_index,
            new_value,
        } => {
            let mut payload = symbol.data().to_vec();
            if payload.is_empty() {
                payload.push(new_value);
            } else {
                let index = usize::from(byte_index) % payload.len();
                payload[index] = new_value;
            }
            let mutated = Symbol::new(symbol.id(), payload, symbol.kind());
            if mutated != *symbol {
                assert!(!tag.verify(&key, &mutated));
            }
        }
        Mutation::MutateObjectId { xor_mask } => {
            let mask = if xor_mask == 0 { 1 } else { xor_mask };
            let mutated_id = SymbolId::new_for_test(
                symbol.id().object_id().as_u128() as u64 ^ mask,
                symbol.sbn(),
                symbol.esi(),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            assert!(!tag.verify(&key, &mutated));
        }
        Mutation::MutateEsi { delta } => {
            let delta = if delta == 0 { 1 } else { delta };
            let mutated_id = SymbolId::new_for_test(
                symbol.id().object_id().as_u128() as u64,
                symbol.sbn(),
                symbol.esi().wrapping_add(delta),
            );
            let mutated = Symbol::new(mutated_id, symbol.data().to_vec(), symbol.kind());
            assert!(!tag.verify(&key, &mutated));
        }
        Mutation::ToggleKind => {
            let toggled_kind = match symbol.kind() {
                SymbolKind::Source => SymbolKind::Repair,
                SymbolKind::Repair => SymbolKind::Source,
            };
            let mutated = Symbol::new(symbol.id(), symbol.data().to_vec(), toggled_kind);
            assert!(!tag.verify(&key, &mutated));
        }
    }
}
