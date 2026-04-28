#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::{
    AUTH_KEY_SIZE, AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext,
};
use asupersync::types::{Symbol, SymbolId, SymbolKind};
use asupersync::util::DetRng;
use hmac::{Hmac, KeyInit, Mac};
use libfuzzer_sys::{Corpus, fuzz_target};
use sha2::Sha256;

const MAX_PAYLOAD_LEN: usize = 512;
const MAX_CHAIN_LEN: usize = 6;
const MAX_LABEL_LEN: usize = 32;
const MAX_CONTEXT_SEGMENTS: usize = 6;
const MAX_CONTEXT_SEGMENT_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    key_source: KeySource,
    primary_chain: Vec<KdfInfoInput>,
    alternate_chain: Vec<KdfInfoInput>,
    symbol: SymbolInput,
    mutation: ContextMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum KeySource {
    Seed(u64),
    Raw([u8; AUTH_KEY_SIZE]),
    DeterministicRng(u64),
}

#[derive(Arbitrary, Debug, Clone)]
struct KdfInfoInput {
    namespace: Namespace,
    label: Vec<u8>,
    context_segments: Vec<Vec<u8>>,
    counter: u16,
    version: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Transport,
    Storage,
    Session,
    Handshake,
    User,
    Empty,
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
enum ContextMutation {
    None,
    BumpCounter { step: u8, delta: u16 },
    ChangeNamespace { step: u8, namespace: Namespace },
    AppendLabelByte { step: u8, byte: u8 },
    ReorderContextSegments { step: u8 },
    DropContextSegment { step: u8, segment: u8 },
}

impl Namespace {
    const fn as_byte(self) -> u8 {
        match self {
            Self::Transport => b'T',
            Self::Storage => b'S',
            Self::Session => b'X',
            Self::Handshake => b'H',
            Self::User => b'U',
            Self::Empty => b'0',
        }
    }

    fn distinct_from(self, candidate: Self) -> Self {
        if self != candidate {
            candidate
        } else {
            match self {
                Self::Transport => Self::Storage,
                Self::Storage => Self::Session,
                Self::Session => Self::Handshake,
                Self::Handshake => Self::User,
                Self::User => Self::Empty,
                Self::Empty => Self::Transport,
            }
        }
    }
}

impl From<SymbolKindInput> for SymbolKind {
    fn from(kind: SymbolKindInput) -> Self {
        match kind {
            SymbolKindInput::Source => Self::Source,
            SymbolKindInput::Repair => Self::Repair,
        }
    }
}

fuzz_target!(|input: FuzzInput| -> Corpus { fuzz_key_derivation_context(input) });

fn fuzz_key_derivation_context(input: FuzzInput) -> Corpus {
    let Some(base_key) = build_base_key(input.key_source) else {
        return Corpus::Reject;
    };

    let primary_chain = normalize_chain(input.primary_chain);
    let alternate_chain = normalize_chain(input.alternate_chain);
    let primary_purposes = encode_chain(&primary_chain);
    let alternate_purposes = encode_chain(&alternate_chain);
    let symbol = build_symbol(input.symbol);

    assert_eq!(derive_key(base_key.clone(), &[]), base_key);
    assert_eq!(encode_chain(&primary_chain), primary_purposes);
    assert_eq!(encode_chain(&alternate_chain), alternate_purposes);
    assert_chain_matches_reference(&base_key, &primary_purposes);
    assert_chain_matches_reference(&base_key, &alternate_purposes);

    let primary_key = derive_key(base_key.clone(), &primary_purposes);
    let repeated_primary_key = derive_key(base_key.clone(), &primary_purposes);
    assert_eq!(
        primary_key, repeated_primary_key,
        "key derivation must be deterministic for the same encoded info chain"
    );

    let primary_tag = AuthenticationTag::compute(&primary_key, &symbol);
    assert!(
        primary_tag.verify(&primary_key, &symbol),
        "freshly derived key must verify its own tag"
    );

    let primary_ctx =
        derive_context_chain(SecurityContext::new(base_key.clone()), &primary_purposes);
    let signed = primary_ctx.sign_symbol(&symbol);
    assert_eq!(
        signed.tag(),
        &primary_tag,
        "SecurityContext::derive_context must match AuthKey::derive_subkey for encoded KDF info"
    );

    let mut received = AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());
    primary_ctx
        .verify_authenticated_symbol(&mut received)
        .expect("same derived context must verify its own signature");
    assert!(received.is_verified());

    let alternate_key = derive_key(base_key.clone(), &alternate_purposes);
    let alternate_ctx =
        derive_context_chain(SecurityContext::new(base_key.clone()), &alternate_purposes);
    let alternate_tag = AuthenticationTag::compute(&alternate_key, &symbol);
    let alternate_signed = alternate_ctx.sign_symbol(&symbol);
    assert_eq!(
        alternate_signed.tag(),
        &alternate_tag,
        "alternate context signing must be deterministic"
    );

    if primary_purposes == alternate_purposes {
        assert_eq!(primary_key, alternate_key);
        assert_eq!(primary_tag, alternate_tag);
    } else if primary_key != alternate_key {
        assert!(
            !primary_tag.verify(&alternate_key, &symbol),
            "a tag from one encoded KDF chain must not verify under a distinct derived key"
        );

        let mut wrong_context_auth =
            AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());
        let wrong_context_result =
            alternate_ctx.verify_authenticated_symbol(&mut wrong_context_auth);
        assert!(wrong_context_result.is_err());
        assert!(!wrong_context_auth.is_verified());
    }

    let mutated_chain = apply_mutation(primary_chain, input.mutation);
    let mutated_purposes = encode_chain(&mutated_chain);
    if mutated_purposes != primary_purposes {
        assert_chain_matches_reference(&base_key, &mutated_purposes);
        let mutated_key = derive_key(base_key.clone(), &mutated_purposes);
        let mutated_ctx =
            derive_context_chain(SecurityContext::new(base_key.clone()), &mutated_purposes);

        if mutated_key != primary_key {
            assert!(
                !primary_tag.verify(&mutated_key, &symbol),
                "rewriting encoded KDF info/context bytes must produce an incompatible key"
            );

            let mut mutated_auth =
                AuthenticatedSymbol::from_parts(signed.into_symbol(), primary_tag);
            let mutated_result = mutated_ctx.verify_authenticated_symbol(&mut mutated_auth);
            assert!(mutated_result.is_err());
            assert!(!mutated_auth.is_verified());
        }
    }

    Corpus::Keep
}

fn build_base_key(source: KeySource) -> Option<AuthKey> {
    match source {
        KeySource::Seed(seed) => {
            let key = AuthKey::from_seed(seed);
            assert_eq!(key, AuthKey::from_seed(seed));
            Some(key)
        }
        KeySource::Raw(bytes) => {
            let key = AuthKey::from_bytes(bytes).ok()?;
            assert_eq!(key.as_bytes(), &bytes);
            Some(key)
        }
        KeySource::DeterministicRng(seed) => {
            let mut rng_a = DetRng::new(seed);
            let key_a = AuthKey::from_rng(&mut rng_a);
            let mut rng_b = DetRng::new(seed);
            let key_b = AuthKey::from_rng(&mut rng_b);
            assert_eq!(key_a, key_b, "from_rng must be reproducible for DetRng");
            Some(key_a)
        }
    }
}

fn normalize_chain(chain: Vec<KdfInfoInput>) -> Vec<KdfInfoInput> {
    chain
        .into_iter()
        .take(MAX_CHAIN_LEN)
        .map(normalize_info)
        .collect()
}

fn normalize_info(mut info: KdfInfoInput) -> KdfInfoInput {
    info.label.truncate(MAX_LABEL_LEN);
    info.context_segments.truncate(MAX_CONTEXT_SEGMENTS);
    for segment in &mut info.context_segments {
        segment.truncate(MAX_CONTEXT_SEGMENT_LEN);
    }
    info
}

fn encode_chain(chain: &[KdfInfoInput]) -> Vec<Vec<u8>> {
    chain.iter().map(encode_kdf_info).collect()
}

fn encode_kdf_info(info: &KdfInfoInput) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"asupersync.kdf.v1");
    encoded.push(info.version);
    encoded.push(info.namespace.as_byte());
    push_len_prefixed(&mut encoded, &info.label);
    encoded.extend_from_slice(&info.counter.to_be_bytes());
    encoded.push(info.context_segments.len() as u8);
    for segment in &info.context_segments {
        push_len_prefixed(&mut encoded, segment);
    }
    encoded
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("segment truncation keeps len in u16 range");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn derive_key(mut key: AuthKey, purposes: &[Vec<u8>]) -> AuthKey {
    for purpose in purposes {
        key = key.derive_subkey(purpose);
    }
    key
}

fn reference_derive_subkey(key: &AuthKey, purpose: &[u8]) -> AuthKey {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(purpose);
    AuthKey::from_hmac_derived(mac.finalize().into_bytes().into())
        .expect("HMAC-derived bytes should satisfy AuthKey validators")
}

fn assert_chain_matches_reference(base_key: &AuthKey, purposes: &[Vec<u8>]) {
    let mut derived = base_key.clone();
    let mut reference = base_key.clone();

    for purpose in purposes {
        derived = derived.derive_subkey(purpose);
        reference = reference_derive_subkey(&reference, purpose);
        assert_eq!(
            derived, reference,
            "derive_subkey step must match direct HMAC-SHA256 reference for encoded KDF info"
        );
    }

    assert_eq!(
        derive_key(base_key.clone(), purposes),
        reference,
        "whole-chain derivation must match the stepwise reference"
    );
}

fn derive_context_chain(mut context: SecurityContext, purposes: &[Vec<u8>]) -> SecurityContext {
    for purpose in purposes {
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

fn apply_mutation(mut chain: Vec<KdfInfoInput>, mutation: ContextMutation) -> Vec<KdfInfoInput> {
    if chain.is_empty() {
        return chain;
    }

    match mutation {
        ContextMutation::None => {}
        ContextMutation::BumpCounter { step, delta } => {
            let idx = usize::from(step) % chain.len();
            let bump = if delta == 0 { 1 } else { delta };
            chain[idx].counter = chain[idx].counter.wrapping_add(bump);
        }
        ContextMutation::ChangeNamespace { step, namespace } => {
            let idx = usize::from(step) % chain.len();
            chain[idx].namespace = chain[idx].namespace.distinct_from(namespace);
        }
        ContextMutation::AppendLabelByte { step, byte } => {
            let idx = usize::from(step) % chain.len();
            if chain[idx].label.len() < MAX_LABEL_LEN {
                chain[idx].label.push(byte);
            } else if let Some(first) = chain[idx].label.first_mut() {
                *first ^= if byte == 0 { 1 } else { byte };
            }
        }
        ContextMutation::ReorderContextSegments { step } => {
            let idx = usize::from(step) % chain.len();
            if chain[idx].context_segments.len() > 1 {
                chain[idx].context_segments.rotate_left(1);
            } else {
                chain[idx].context_segments.push(vec![0xFF]);
            }
        }
        ContextMutation::DropContextSegment { step, segment } => {
            let idx = usize::from(step) % chain.len();
            if chain[idx].context_segments.is_empty() {
                chain[idx].context_segments.push(vec![0x01]);
            } else {
                let remove = usize::from(segment) % chain[idx].context_segments.len();
                chain[idx].context_segments.remove(remove);
            }
        }
    }

    chain.into_iter().map(normalize_info).collect()
}
