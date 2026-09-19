use super::*;
use crate::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::types::symbol::{ObjectId, Symbol, SymbolId, SymbolKind};

fn limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 8192, max_symbols: 16, max_payload_bytes: 4096, max_decoded_bytes: 8192 }
}
fn storage() -> SymbolStoreLimits {
    SymbolStoreLimits { max_batches: 4, max_bytes: 32768, max_batches_per_peer: 2, max_bytes_per_peer: 16384 }
}
fn symbols(object: u128, payload: &[u8]) -> Vec<AuthenticatedSymbol> {
    let security = SecurityContext::new(AuthKey::from_seed(42));
    [2, 0, 1].into_iter().map(|esi| security.sign_symbol(&Symbol::new(
        SymbolId::new(ObjectId::from_u128(object), 0, esi), payload.to_vec(), SymbolKind::Source,
    ))).collect()
}
fn encoded(object: u128) -> EncodedSymbolBatch {
    encode_symbol_batch(&symbols(object, b"retained payload"), limits()).unwrap()
}
fn store(bounds: SymbolStoreLimits) -> SymbolReplicaStore {
    SymbolReplicaStore::new("replica-a", AuthKey::from_seed(42), limits(), bounds).unwrap()
}

#[test]
fn canonical_roundtrip_preserves_symbols_and_authentication() {
    let mut original = symbols(5, b"abc");
    let first = encode_symbol_batch(&original, limits()).unwrap();
    original.reverse();
    let second = encode_symbol_batch(&original, limits()).unwrap();
    assert_eq!(first.as_ref(), second.as_ref());
    assert_eq!(first.key(), second.key());
    let decoded = decode_symbol_batch(first.as_ref(), &AuthKey::from_seed(42), limits()).unwrap();
    assert_eq!(decoded.iter().map(|s| s.symbol().esi()).collect::<Vec<_>>(), vec![0, 1, 2]);
    assert!(decoded.iter().all(AuthenticatedSymbol::is_verified));
    assert_eq!(encode_symbol_batch(&decoded, limits()).unwrap().as_ref(), first.as_ref());
}

#[test]
fn empty_mixed_and_duplicate_batches_refuse() {
    assert!(matches!(encode_symbol_batch(&[], limits()), Err(SymbolStoreError::Empty)));
    let mut input = symbols(1, b"x");
    input.push(input[0].clone());
    assert!(matches!(encode_symbol_batch(&input, limits()), Err(SymbolStoreError::Identity)));
    input = symbols(1, b"x");
    input.push(symbols(2, b"x").remove(0));
    assert!(matches!(encode_symbol_batch(&input, limits()), Err(SymbolStoreError::Identity)));
}

#[test]
fn every_truncated_prefix_and_single_bit_mutation_is_rejected() {
    let bytes = encoded(1);
    let key = AuthKey::from_seed(42);
    for end in 0..bytes.as_ref().len() {
        assert!(decode_symbol_batch(&bytes.as_ref()[..end], &key, limits()).is_err(), "prefix {end}");
    }
    for offset in 0..bytes.as_ref().len() {
        for bit in 0..8 {
            let mut changed = bytes.as_ref().to_vec();
            changed[offset] ^= 1 << bit;
            assert!(decode_symbol_batch(&changed, &key, limits()).is_err(), "byte {offset}, bit {bit}");
        }
    }
}

#[test]
fn receiver_reverifies_tags_and_never_trusts_verified_flag() {
    let bytes = encoded(1);
    assert!(matches!(decode_symbol_batch(bytes.as_ref(), &AuthKey::from_seed(43), limits()), Err(SymbolStoreError::Authentication)));
    let raw = symbols(1, b"forged").remove(0).into_symbol();
    let forged = AuthenticatedSymbol::new_verified(raw, AuthenticationTag::from_bytes([9; 32]));
    assert!(forged.is_verified());
    let encoded = encode_symbol_batch(&[forged], limits()).unwrap();
    assert!(matches!(decode_symbol_batch(encoded.as_ref(), &AuthKey::from_seed(42), limits()), Err(SymbolStoreError::Authentication)));
}

#[test]
fn independent_batch_limits_and_trailing_bytes_fail_closed() {
    let bytes = encoded(1);
    for which in 0..4 {
        let mut bounds = limits();
        match which {
            0 => bounds.max_encoded_bytes = bytes.as_ref().len() - 1,
            1 => bounds.max_symbols = 2,
            2 => bounds.max_payload_bytes = 1,
            _ => bounds.max_decoded_bytes = 1,
        }
        assert!(decode_symbol_batch(bytes.as_ref(), &AuthKey::from_seed(42), bounds).is_err());
    }
    let mut bytes = bytes.as_ref().to_vec();
    bytes.push(0);
    assert!(matches!(decode_symbol_batch(&bytes, &AuthKey::from_seed(42), limits()), Err(SymbolStoreError::TrailingData)));
    bytes[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(decode_symbol_batch(&bytes, &AuthKey::from_seed(42), limits()), Err(SymbolStoreError::Limit("symbols"))));
}

#[test]
fn identical_retries_reuse_storage_at_full_capacity() {
    let bytes = encoded(1);
    let store = store(SymbolStoreLimits {
        max_batches: 1, max_bytes: bytes.as_ref().len(),
        max_batches_per_peer: 1, max_bytes_per_peer: bytes.as_ref().len(),
    });
    let peer = NodeId::new("origin");
    let first = store.put(&peer, bytes.as_ref()).unwrap();
    let second = store.put(&peer, bytes.as_ref()).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(store.stats(), SymbolStoreStats { batches: 1, bytes: bytes.as_ref().len() });
}

#[test]
fn conflicting_reuse_does_not_replace_retained_object() {
    let store = store(storage());
    let peer = NodeId::new("origin");
    let original = encoded(1);
    store.put(&peer, original.as_ref()).unwrap();
    let changed = encode_symbol_batch(&symbols(1, b"changed"), limits()).unwrap();
    assert!(matches!(store.put(&peer, changed.as_ref()), Err(SymbolStoreError::Conflict)));
    assert_eq!(store.get(&peer, original.key()).unwrap().as_ref().as_ref(), original.as_ref());
    assert!(matches!(store.get(&peer, changed.key()), Err(SymbolStoreError::NotFound)));
}

#[test]
fn namespaces_and_exact_digest_isolate_reads() {
    let store = store(storage());
    let bytes = encoded(1);
    let owner = NodeId::new("owner");
    let stranger = NodeId::new("stranger");
    store.put(&owner, bytes.as_ref()).unwrap();
    assert!(matches!(store.get(&stranger, bytes.key()), Err(SymbolStoreError::NotFound)));
    let mut wrong_key = bytes.key();
    wrong_key.digest[0] ^= 1;
    assert!(matches!(store.get(&owner, wrong_key), Err(SymbolStoreError::NotFound)));
    store.put(&stranger, bytes.as_ref()).unwrap();
    assert_eq!(store.stats().batches, 2);
}

#[test]
fn global_and_per_peer_capacity_are_independent() {
    let a = NodeId::new("a"); let b = NodeId::new("b");
    let store = store(SymbolStoreLimits { max_batches: 2, max_batches_per_peer: 1, ..storage() });
    store.put(&a, encoded(1).as_ref()).unwrap();
    assert!(matches!(store.put(&a, encoded(2).as_ref()), Err(SymbolStoreError::Limit("peer batches"))));
    store.put(&b, encoded(2).as_ref()).unwrap();
    assert!(matches!(store.put(&NodeId::new("c"), encoded(3).as_ref()), Err(SymbolStoreError::Limit("batches"))));
}

#[test]
fn global_and_per_peer_byte_ceilings_are_independent() {
    let bytes = encoded(1);
    for per_peer in [false, true] {
        let mut bounds = storage();
        if per_peer { bounds.max_bytes_per_peer = bytes.as_ref().len() - 1; }
        else { bounds.max_bytes = bytes.as_ref().len() - 1; }
        let store = store(bounds);
        assert!(store.put(&NodeId::new("a"), bytes.as_ref()).is_err());
        assert_eq!(store.stats(), SymbolStoreStats { batches: 0, bytes: 0 });
    }
}

#[test]
fn failed_last_symbol_authentication_cannot_publish_a_prefix() {
    let store = store(storage());
    let peer = NodeId::new("a");
    let original = encoded(1);
    store.put(&peer, original.as_ref()).unwrap();
    let before = store.stats();
    let mut corrupt = encoded(2).as_ref().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(store.put(&peer, &corrupt), Err(SymbolStoreError::Authentication)));
    assert_eq!(store.stats(), before);
    assert!(store.get(&peer, original.key()).is_ok());
}

#[test]
fn racing_writers_cannot_oversubscribe_capacity() {
    let store = Arc::new(store(SymbolStoreLimits { max_batches: 1, ..storage() }));
    let gate = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = [1, 2].into_iter().map(|object| {
        let store = Arc::clone(&store); let gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            let bytes = encoded(object);
            gate.wait();
            store.put(&NodeId::new("a"), bytes.as_ref()).is_ok()
        })
    }).collect();
    let accepted = threads.into_iter().map(|thread| usize::from(thread.join().unwrap())).sum::<usize>();
    assert_eq!(accepted, 1);
    assert_eq!(store.stats().batches, 1);
}

#[test]
fn zero_storage_and_invalid_identities_never_publish() {
    let store = store(SymbolStoreLimits { max_batches: 0, ..storage() });
    assert!(store.put(&NodeId::new("a"), encoded(1).as_ref()).is_err());
    assert!(matches!(store.put(&NodeId::new(""), encoded(1).as_ref()), Err(SymbolStoreError::InvalidIdentity)));
    assert_eq!(store.stats().batches, 0);
    assert!(SymbolReplicaStore::new("", AuthKey::from_seed(42), limits(), storage()).is_err());
}

#[test]
fn debug_omits_payload_key_and_peer_names() {
    let store = store(storage());
    let bytes = encoded(1);
    store.put(&NodeId::new("private-origin"), bytes.as_ref()).unwrap();
    let text = format!("{store:?} {bytes:?} {:?}", bytes.key());
    assert!(!text.contains("retained payload"));
    assert!(!text.contains("private-origin"));
    assert!(!text.contains("digest"));
}
