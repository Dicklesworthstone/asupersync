use super::*;
use crate::types::RegionId;

fn limits() -> ManifestLimits {
    ManifestLimits { max_encoded_bytes: 4096, max_replicas: 8, max_decoded_bytes: 4096 }
}
fn identity() -> SnapshotIdentity {
    SnapshotIdentity { region_id: RegionId::new_for_test(7, 3), origin_id: 11, epoch: 13, sequence: 17 }
}
fn params() -> ObjectParams { ObjectParams::new(ObjectId::new(19, 23), 1024, 128, 2, 4) }
fn replicas() -> Vec<ReplicaFetch> {
    ["z", "a"].into_iter().map(|name| ReplicaFetch {
        replica_id: name.into(), key: SymbolBatchKey { object_id: params().object_id, digest: [name.as_bytes()[0]; 32] },
    }).collect()
}
fn manifest() -> RecoveryManifest {
    RecoveryManifest::new(NodeId::new("origin"), params(), identity(), replicas(), 1, limits()).unwrap()
}
fn bytes() -> ManifestBytes { manifest().to_canonical_bytes(&AuthKey::from_seed(99), 4096).unwrap() }
fn decode(bytes: &[u8]) -> Result<RecoveryManifest, ManifestError> {
    RecoveryManifest::from_canonical_bytes(bytes, &AuthKey::from_seed(99), identity(), &NodeId::new("origin"), limits())
}
fn resign(bytes: &mut [u8]) {
    let end = bytes.len() - TAG;
    let tag = AuthenticationTag::compute_for_domain_payload(&AuthKey::from_seed(99), DOMAIN, &bytes[..end]);
    bytes[end..].copy_from_slice(tag.as_bytes());
}

#[test]
fn canonical_roundtrip_preserves_all_recovery_inputs_without_source_owners() {
    let original = manifest();
    let bytes = original.to_canonical_bytes(&AuthKey::from_seed(99), 4096).unwrap();
    drop(original);
    let restored = decode(bytes.as_ref()).unwrap();
    assert_eq!(restored.identity(), identity());
    assert_eq!(restored.params().object_id, params().object_id);
    assert_eq!(restored.params().object_size, 1024);
    assert_eq!(restored.params().source_blocks, 2);
    assert_eq!(restored.params().symbols_per_block, 4);
    assert_eq!(restored.params().symbol_size, 128);
    assert_eq!(restored.minimum_replicas(), 1);
    assert_eq!(restored.peer_node(), &NodeId::new("origin"));
    assert_eq!(restored.replicas()[0].replica_id, "a");
    assert_eq!(restored.replicas()[1].replica_id, "z");
    assert_eq!(restored.replicas()[0].key.digest, [b'a'; 32]);
    assert_eq!(restored.to_canonical_bytes(&AuthKey::from_seed(99), 4096).unwrap().as_ref(), bytes.as_ref());
}

#[test]
fn insertion_order_does_not_change_authenticated_bytes() {
    let mut entries = replicas(); entries.reverse();
    let reversed = RecoveryManifest::new(NodeId::new("origin"), params(), identity(), entries, 1, limits()).unwrap();
    assert_eq!(bytes().as_ref(), reversed.to_canonical_bytes(&AuthKey::from_seed(99), 4096).unwrap().as_ref());
}

#[test]
fn every_truncation_and_single_bit_mutation_is_rejected() {
    let encoded = bytes(); let original = encoded.as_ref();
    for cut in 0..original.len() { assert!(decode(&original[..cut]).is_err(), "prefix {cut}"); }
    for index in 0..original.len() {
        for bit in 0..8 {
            let mut changed = original.to_vec(); changed[index] ^= 1 << bit;
            assert!(decode(&changed).is_err(), "byte {index} bit {bit}");
        }
    }
}

#[test]
fn valid_signature_never_overrides_expected_generation_branch_sequence_or_peer() {
    let encoded = bytes();
    for field in 0..4 {
        let mut wrong = identity();
        match field {
            0 => wrong.region_id = RegionId::new_for_test(7, 4),
            1 => wrong.origin_id += 1,
            2 => wrong.epoch += 1,
            _ => wrong.sequence += 1,
        }
        assert!(matches!(RecoveryManifest::from_canonical_bytes(encoded.as_ref(), &AuthKey::from_seed(99),
            wrong, &NodeId::new("origin"), limits()), Err(ManifestError::Identity)));
    }
    assert!(matches!(RecoveryManifest::from_canonical_bytes(encoded.as_ref(), &AuthKey::from_seed(99),
        identity(), &NodeId::new("other"), limits()), Err(ManifestError::Identity)));
}

#[test]
fn author_key_is_independent_and_zero_tag_is_not_authentication() {
    let encoded = bytes();
    assert!(matches!(RecoveryManifest::from_canonical_bytes(encoded.as_ref(), &AuthKey::from_seed(42),
        identity(), &NodeId::new("origin"), limits()), Err(ManifestError::Authentication)));
    let mut changed = encoded.as_ref().to_vec(); let end = changed.len() - TAG;
    changed[end..].fill(0);
    assert!(matches!(decode(&changed), Err(ManifestError::Authentication)));
}

#[test]
fn exact_bounds_succeed_and_each_smaller_bound_refuses() {
    let encoded = bytes();
    let exact = ManifestLimits {
        max_encoded_bytes: encoded.as_ref().len(), max_replicas: 2,
        max_decoded_bytes: 2 * std::mem::size_of::<ReplicaFetch>() + 8,
    };
    RecoveryManifest::from_canonical_bytes(encoded.as_ref(), &AuthKey::from_seed(99), identity(),
        &NodeId::new("origin"), exact).unwrap();
    for field in 0..3 {
        let mut smaller = exact;
        match field { 0 => smaller.max_encoded_bytes -= 1, 1 => smaller.max_replicas -= 1, _ => smaller.max_decoded_bytes -= 1 }
        assert!(matches!(RecoveryManifest::from_canonical_bytes(encoded.as_ref(), &AuthKey::from_seed(99),
            identity(), &NodeId::new("origin"), smaller), Err(ManifestError::Limit(_))));
    }
    assert!(manifest().to_canonical_bytes(&AuthKey::from_seed(99), encoded.as_ref().len() - 1).is_err());
}

#[test]
fn constructor_rejects_duplicate_mixed_empty_and_impossible_plans() {
    for case in 0..5 {
        let mut entries = replicas(); let mut minimum = 1;
        match case {
            0 => entries[1].replica_id = entries[0].replica_id.clone(),
            1 => entries[1].key.object_id = ObjectId::NIL,
            2 => entries.clear(),
            3 => minimum = 0,
            _ => minimum = 3,
        }
        assert!(matches!(RecoveryManifest::new(NodeId::new("origin"), params(), identity(), entries,
            minimum, limits()), Err(ManifestError::Format)));
    }
}

#[test]
fn decoded_threshold_and_counts_cannot_bypass_semantic_limits_even_when_resigned() {
    for (offset, value) in [(74, 0_u32), (74, 3), (78, 0), (78, u32::MAX)] {
        let mut changed = bytes().as_ref().to_vec();
        changed[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); resign(&mut changed);
        assert!(decode(&changed).is_err());
    }
}

#[test]
fn invalid_dimensions_refuse_before_any_decoder_exists() {
    for offset in [60, 68, 70, 72] {
        let mut changed = bytes().as_ref().to_vec();
        let n = if offset == 60 { 8 } else { 2 };
        changed[offset..offset + n].fill(0); resign(&mut changed);
        assert!(matches!(decode(&changed), Err(ManifestError::Format)));
    }
    let mut wrong = params(); wrong.source_blocks = 3;
    assert!(matches!(RecoveryManifest::new(NodeId::new("origin"), wrong, identity(), replicas(), 1, limits()),
        Err(ManifestError::Format)));
}

#[test]
fn noncanonical_names_and_trailing_bytes_fail_even_with_valid_authentication() {
    let original = bytes(); let first_label = HEADER + "origin".len() + 1;
    for (index, value) in [(first_label, b'z'), (first_label, 255), (HEADER - 1, 0)] {
        let mut changed = original.as_ref().to_vec(); changed[index] = value; resign(&mut changed);
        assert!(decode(&changed).is_err());
    }
    let mut changed = original.as_ref().to_vec(); let end = changed.len() - TAG;
    changed.insert(end, 0); resign(&mut changed);
    assert!(matches!(decode(&changed), Err(ManifestError::TrailingData)));
}

#[test]
fn label_byte_bounds_are_enforced_for_utf8_and_long_identities() {
    for name in [String::new(), "x".repeat(256), "é".repeat(128)] {
        assert!(RecoveryManifest::new(NodeId::new(&name), params(), identity(), replicas(), 1, limits()).is_err());
        let mut entries = replicas(); entries[0].replica_id = name;
        assert!(RecoveryManifest::new(NodeId::new("origin"), params(), identity(), entries, 1, limits()).is_err());
    }
    let name = "é".repeat(127);
    let manifest = RecoveryManifest::new(NodeId::new(&name), params(), identity(), replicas(), 1, limits()).unwrap();
    let encoded = manifest.to_canonical_bytes(&AuthKey::from_seed(99), 4096).unwrap();
    RecoveryManifest::from_canonical_bytes(encoded.as_ref(), &AuthKey::from_seed(99), identity(), &NodeId::new(name), limits()).unwrap();
}

#[test]
fn debug_omits_origin_topology_and_digest_values() {
    let manifest = manifest();
    let text = format!("{manifest:?} {:?}", bytes());
    assert!(!text.contains("origin")); assert!(!text.contains("ASUPMNF"));
    assert!(text.contains("minimum_replicas"));
}
