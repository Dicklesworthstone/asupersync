    use super::*;
    use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
    use crate::atp::object::{ContentId, MetadataPolicy, Object, ObjectGraph};

    fn chunk(index: u32, offset: u64, bytes: &[u8]) -> ChunkBoundary {
        ChunkBoundary {
            index,
            byte_offset: offset,
            size_bytes: bytes.len() as u64,
            content_hash: Sha256::digest(bytes).into(),
            strategy: ChunkStrategy::FixedSize,
            metadata: None,
        }
    }

    fn legacy_root(manifest: &Manifest) -> MerkleRoot {
        MerkleRoot::from_manifest_components(
            &manifest.objects,
            &manifest.chunk_plan,
            &manifest.raptorq_layout,
            &manifest.compression_policy,
            &manifest.encryption_policy,
            &manifest.capability_policy,
            &manifest.transform_order,
            &manifest.transform_proof_policy,
            &manifest.repair_groups,
        )
    }

    fn sample() -> Manifest {
        let mut graph = ObjectGraph::new();
        graph.add_root(Object::file(b"abcdefgh".to_vec())).unwrap();
        let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
        manifest.objects.values_mut().next().unwrap().chunk_boundaries = vec![
            chunk(0, 0, b"abcd"),
            chunk(1, 4, b"efgh"),
        ];
        manifest.merkle_root = legacy_root(&manifest);
        manifest.validate().unwrap();
        manifest
    }

    #[test]
    fn roundtrip_preserves_the_legacy_manifest_and_root() {
        let manifest = sample();
        let original = manifest.clone();
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        assert_eq!(ManifestChunkCommitment::new(*expected.hash()), expected);
        expected.verify(&manifest).unwrap();
        assert_eq!(manifest, original);
        assert_eq!(legacy_root(&manifest), original.merkle_root);
    }

    #[test]
    fn every_canonical_chunk_field_is_bound_even_when_the_legacy_root_is_unchanged() {
        let original = sample();
        let expected = ManifestChunkCommitment::from_manifest(&original).unwrap();
        for mutation in 0..5 {
            let mut tampered = original.clone();
            let chunk = &mut tampered.objects.values_mut().next().unwrap().chunk_boundaries[1];
            match mutation {
                0 => chunk.index += 1,
                1 => chunk.byte_offset += 1,
                2 => chunk.size_bytes -= 1,
                3 => chunk.content_hash[0] ^= 1,
                4 => chunk.strategy = ChunkStrategy::ObjectSpecific,
                _ => unreachable!(),
            }
            tampered.validate().unwrap();
            assert_eq!(legacy_root(&tampered), original.merkle_root);
            assert_eq!(expected.verify(&tampered), Err(ManifestChunkCommitmentError::Mismatch));
        }
    }

    #[test]
    fn chunk_insertion_deletion_and_empty_ledger_cannot_reuse_a_commitment() {
        let original = sample();
        let expected = ManifestChunkCommitment::from_manifest(&original).unwrap();
        for mutation in 0..3 {
            let mut tampered = original.clone();
            let chunks = &mut tampered.objects.values_mut().next().unwrap().chunk_boundaries;
            match mutation {
                0 => { chunks.pop(); }
                1 => chunks.clear(),
                2 => chunks.push(chunk(2, 8, b"tail")),
                _ => unreachable!(),
            }
            tampered.validate().unwrap();
            assert_eq!(expected.verify(&tampered), Err(ManifestChunkCommitmentError::Mismatch));
        }
    }

    #[test]
    fn structural_rejection_precedes_commitment_acceptance() {
        let mut manifest = sample();
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        manifest.objects.values_mut().next().unwrap().chunk_boundaries.reverse();
        assert!(matches!(expected.verify(&manifest),
            Err(ManifestChunkCommitmentError::InvalidManifest(_))));
    }

    #[test]
    fn chunk_ledgers_are_bound_to_their_own_objects() {
        let mut graph = ObjectGraph::new();
        let first = Object::file(b"abcdefgh".to_vec());
        let second = Object::file(b"ijklmnop".to_vec());
        let first_id = first.id.clone();
        let second_id = second.id.clone();
        graph.add_root(first).unwrap();
        graph.add_root(second).unwrap();
        let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
        let a = vec![chunk(0, 0, b"abcdefgh")];
        let b = vec![chunk(0, 0, b"ijklmnop")];
        manifest.objects.get_mut(&first_id).unwrap().chunk_boundaries = a.clone();
        manifest.objects.get_mut(&second_id).unwrap().chunk_boundaries = b.clone();
        manifest.merkle_root = legacy_root(&manifest);
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        manifest.objects.get_mut(&first_id).unwrap().chunk_boundaries = b;
        manifest.objects.get_mut(&second_id).unwrap().chunk_boundaries = a;
        manifest.validate().unwrap();
        assert_eq!(expected.verify(&manifest), Err(ManifestChunkCommitmentError::Mismatch));
    }

    #[test]
    fn inconsistent_object_identity_cannot_be_committed() {
        let mut manifest = sample();
        manifest.objects.values_mut().next().unwrap().id =
            ObjectId::content(ContentId::from_bytes(b"another object"));
        manifest.validate().unwrap();
        assert_eq!(ManifestChunkCommitment::from_manifest(&manifest),
            Err(ManifestChunkCommitmentError::ObjectIdentityMismatch));
    }

    #[test]
    fn changed_whole_object_hash_cannot_reuse_a_chunk_commitment() {
        let mut manifest = sample();
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        manifest.objects.values_mut().next().unwrap().content_hash = None;
        manifest.merkle_root = legacy_root(&manifest);
        manifest.validate().unwrap();
        assert_eq!(expected.verify(&manifest), Err(ManifestChunkCommitmentError::Mismatch));
    }
