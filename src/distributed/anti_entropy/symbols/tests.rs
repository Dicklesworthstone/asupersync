use super::*;
use crate::distributed::anti_entropy::catalog::{bucket, leaf_hash};
use crate::distributed::symbol_service::{SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch};
use crate::security::{AuthKey, SecurityContext};
use crate::types::symbol::Symbol;

fn limits() -> CatalogLimits {
    CatalogLimits { depth: 3, max_entries: 16, max_key_bytes: 32, max_total_key_bytes: 512,
        max_page_entries: 8, max_retained_bytes: 16_384, max_response_bytes: 4096 }
}

fn store() -> SymbolReplicaStore {
    SymbolReplicaStore::new("source", AuthKey::from_seed(42),
        SymbolBatchLimits { max_encoded_bytes: 2048, max_symbols: 8, max_payload_bytes: 1024, max_decoded_bytes: 4096 },
        SymbolStoreLimits { max_batches: 8, max_bytes: 16_384, max_batches_per_peer: 8, max_bytes_per_peer: 16_384 }).unwrap()
}

fn put(store: &SymbolReplicaStore, origin: &NodeId, object: u64) -> SymbolBatchKey {
    let security = SecurityContext::new(AuthKey::from_seed(42));
    let symbol = security.sign_symbol(&Symbol::new_for_test(object, 0, 0, b"retained catalog fixture"));
    let encoded = encode_symbol_batch(&[symbol], SymbolBatchLimits { max_encoded_bytes: 2048,
        max_symbols: 8, max_payload_bytes: 1024, max_decoded_bytes: 4096 }).unwrap();
    store.put(origin, encoded.as_ref()).unwrap().key()
}

#[test]
fn symbol_catalog_atomic_cut_is_origin_scoped_and_requires_explicit_new_revision() {
    let store = store();
    let alice = NodeId::new("alice");
    let bob = NodeId::new("bob");
    let first = put(&store, &alice, 1);
    let secret = put(&store, &bob, 2);
    let catalog = Arc::new(capture_symbol_catalog(&store, alice.clone(), 7, limits()).unwrap());
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog.find(&first.object_id.as_u128().to_le_bytes()).unwrap().value_hash, first.digest);
    assert!(catalog.find(&secret.object_id.as_u128().to_le_bytes()).is_none());
    put(&store, &alice, 3);
    assert_eq!(catalog.len(), 1, "later retained batches do not mutate an immutable cut");
    let service = SymbolCatalogService::new("source", 2, 32_768).unwrap();
    service.publish(Arc::clone(&catalog)).unwrap();
    service.publish(Arc::new(capture_symbol_catalog(&store, bob.clone(), 1, limits()).unwrap())).unwrap();
    let request = wire::request("source", None).unwrap();
    let alice_root = wire::root(&service.handle(&alice, &request).unwrap(), &alice, limits()).unwrap();
    assert_eq!(alice_root.entries, 1);
    assert!(wire::root(&service.handle(&bob, &request).unwrap(), &alice, limits()).is_err());
    assert_eq!(service.handle(&NodeId::new("stranger"), &request), Err(CatalogError::Unauthorized));
    let old_node = wire::request("source", Some((catalog.snapshot_id(), 1))).unwrap();
    assert_eq!(service.handle(&bob, &old_node), Err(CatalogError::SnapshotChanged));
    assert!(service.publish(Arc::new(capture_symbol_catalog(&store, alice.clone(), 7, limits()).unwrap())).is_err());
    service.publish(Arc::new(capture_symbol_catalog(&store, alice.clone(), 8, limits()).unwrap())).unwrap();
    assert_eq!(service.handle(&alice, &old_node), Err(CatalogError::SnapshotChanged));
    assert_eq!(catalog.len(), 1, "published replacements leave retained old owners immutable");
}

#[test]
fn strong_catalog_pages_bind_every_full_key_value_length_order_and_snapshot() {
    let store = store();
    let origin = NodeId::new("origin");
    for object in 1..=5 { put(&store, &origin, object); }
    let catalog = capture_symbol_catalog(&store, origin.clone(), 4, limits()).unwrap();
    let root_bytes = wire::serve(&catalog, "source", &wire::request("source", None).unwrap()).unwrap();
    let root = wire::root(&root_bytes, &origin, limits()).unwrap();
    let mut frontier = vec![(1, root.root)];
    let mut keys = Vec::new();
    let mut examined = 0;
    while let Some((index, expected)) = frontier.pop() {
        let input = wire::request("source", Some((root.snapshot, index))).unwrap();
        let bytes = wire::serve(&catalog, "source", &input).unwrap();
        examined += 1;
        match wire::page(&bytes, root, limits(), index, expected).unwrap() {
            wire::Page::Branch(left, right) => {
                let mut corrupt = bytes.clone();
                *corrupt.last_mut().unwrap() ^= 1;
                assert!(matches!(wire::page(&corrupt, root, limits(), index, expected), Err(CatalogError::Integrity)));
                frontier.extend([(index * 2, left), (index * 2 + 1, right)]);
            }
            wire::Page::Leaf(entries) => {
                assert_eq!(leaf_hash(limits().depth, index, &entries), expected);
                for entry in &entries {
                    assert_eq!(bucket(limits().depth, &entry.key), index as usize - 8);
                }
                keys.extend(entries.into_iter().map(|entry| entry.key));
                let mut trailing = bytes.clone();
                trailing.push(0);
                assert!(wire::page(&trailing, root, limits(), index, expected).is_err());
            }
        }
    }
    assert_eq!(examined, 15);
    assert_eq!(keys.len(), 5);
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 5);
    for length in 0..root_bytes.len() { assert!(wire::root(&root_bytes[..length], &origin, limits()).is_err()); }
    let mut wrong_limits = limits();
    wrong_limits.max_page_entries += 1;
    assert_eq!(wire::root(&root_bytes, &origin, wrong_limits), Err(CatalogError::Configuration));
    assert!(wire::serve(&catalog, "source", &wire::request("other", None).unwrap()).is_err());
}

#[test]
fn catalog_refuses_overfull_pages_duplicate_keys_and_real_allocation_capacity() {
    let origin = NodeId::new("origin");
    let mut entries = Vec::new();
    for n in 0_u128..256 {
        let key = n.to_le_bytes().to_vec();
        if bucket(limits().depth, &key) == 0 {
            entries.push(CatalogEntry { key, value_hash: [n as u8; 32], value_bytes: 17 });
            if entries.len() == 2 { break; }
        }
    }
    assert_eq!(entries.len(), 2);
    let catalog = Catalog::new(origin.clone(), 1, entries.clone(), limits()).unwrap();
    let reversed = Catalog::new(origin.clone(), 1, entries.iter().rev().cloned().collect(), limits()).unwrap();
    assert_eq!(catalog.snapshot_id(), reversed.snapshot_id());
    let mut page_limits = limits();
    page_limits.max_page_entries = 1;
    assert!(matches!(Catalog::new(origin.clone(), 1, entries.clone(), page_limits), Err(CatalogError::Limit("leaf entries"))));
    let mut frame_limits = limits();
    frame_limits.max_response_bytes = 133;
    assert!(matches!(Catalog::new(origin.clone(), 1, entries.clone(), frame_limits), Err(CatalogError::Limit("response bytes"))));
    assert!(matches!(Catalog::new(origin.clone(), 1, vec![entries[0].clone(), entries[0].clone()], limits()), Err(CatalogError::Conflict)));
    let mut oversized_capacity = Vec::with_capacity(20_000);
    oversized_capacity.extend_from_slice(&entries[0].key);
    assert!(matches!(Catalog::new(origin, 1, vec![CatalogEntry { key: oversized_capacity,
        value_hash: [0; 32], value_bytes: 1 }], limits()), Err(CatalogError::Limit("retained bytes"))));
}

#[test]
fn remote_leaf_admission_charges_entry_and_key_allocations_before_copying() {
    let origin = NodeId::new("origin");
    let mut policy = limits();
    policy.max_entries = 32;
    policy.max_page_entries = 32;
    policy.max_total_key_bytes = 512;
    let entries = (0_u128..4096).map(|n| n.to_le_bytes().to_vec())
        .filter(|key| bucket(policy.depth, key) == 0).take(32)
        .map(|key| CatalogEntry { key, value_hash: [42; 32], value_bytes: 17 }).collect::<Vec<_>>();
    assert_eq!(entries.len(), 32);
    let source = Catalog::new(origin.clone(), 1, entries, policy).unwrap();
    let mut bytes = wire::serve(&source, "source", &wire::request("source", Some((source.snapshot_id(), 8))).unwrap()).unwrap();

    // A malicious authenticated source may assert a root whose page cannot fit
    // the agreed memory policy. Even a completely empty local tree fits here;
    // the remote entry-vector request alone does not and must refuse first.
    policy.max_retained_bytes = 700;
    assert!(Catalog::new(origin.clone(), 0, Vec::new(), policy).is_ok());
    assert!(32 * std::mem::size_of::<CatalogEntry>() > policy.max_retained_bytes);
    let root = wire::Root { snapshot: super::super::catalog::snapshot_hash(&origin, 1, policy,
        source.root(), source.len(), source.key_bytes()), revision: 1,
        root: source.root(), entries: source.len(), key_bytes: source.key_bytes() };
    bytes[12..44].copy_from_slice(&root.snapshot);
    assert!(matches!(wire::page(&bytes, root, policy, 8, source.node(8).unwrap()),
        Err(CatalogError::Limit("page bytes"))));

    // A one-entry vector fits exactly, but even its first nonempty key does not.
    // This probes the independent pre-copy admission check rather than relying
    // on a final oversized page or a failed digest after allocations happened.
    let mut single_policy = limits();
    let entry = CatalogEntry { key: vec![0; 16], value_hash: [7; 32], value_bytes: 1 };
    let index = 8 + bucket(single_policy.depth, &entry.key) as u32;
    let single = Catalog::new(origin, 2, vec![entry], single_policy).unwrap();
    let bytes = wire::serve(&single, "source", &wire::request("source", Some((single.snapshot_id(), index))).unwrap()).unwrap();
    let root = wire::Root { snapshot: single.snapshot_id(), revision: 2, root: single.root(), entries: 1, key_bytes: 16 };
    single_policy.max_retained_bytes = std::mem::size_of::<CatalogEntry>();
    assert!(matches!(wire::page(&bytes, root, single_policy, index, single.node(index).unwrap()),
        Err(CatalogError::Limit("page bytes"))));
}
