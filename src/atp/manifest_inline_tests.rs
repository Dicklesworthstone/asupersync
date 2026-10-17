    use super::*;
    use crate::atp::object::{ContentId, Object};

    #[test]
    fn manifest_version_support_check_works() {
        assert!(ManifestVersion::CURRENT.is_supported());
        assert!(ManifestVersion(0).is_supported());
        assert!(!ManifestVersion(100).is_supported());
    }

    #[test]
    fn merkle_root_from_empty_graph() {
        let graph = ObjectGraph::new();
        let root = MerkleRoot::from_graph(&graph);

        // Empty graph should have consistent root
        let root2 = MerkleRoot::from_graph(&graph);
        assert_eq!(root, root2);
    }

    #[test]
    fn deterministic_f32_manifest_bytes_are_stable() {
        assert_eq!(
            deterministic_f32_be_bytes(10.0),
            10.0_f32.to_bits().to_be_bytes()
        );
        assert_eq!(
            deterministic_f32_be_bytes(f32::from_bits(0x7fc0_0001)),
            0x7fc0_0000_u32.to_be_bytes()
        );
        assert_eq!(
            deterministic_f32_be_bytes(-0.0),
            deterministic_f32_be_bytes(0.0)
        );
    }

    #[test]
    fn deterministic_f32_be_bytes_canonical_nan() {
        // Any NaN should map to canonical NaN
        let nan1 = f32::from_bits(0x7fc0_0001); // Signaling NaN
        let nan2 = f32::from_bits(0x7ff0_1234); // Quiet NaN with payload
        let nan3 = f32::NAN; // Standard NaN

        let expected = [0x7f, 0xc0, 0x00, 0x00]; // Canonical NaN in big-endian
        assert_eq!(deterministic_f32_be_bytes(nan1), expected);
        assert_eq!(deterministic_f32_be_bytes(nan2), expected);
        assert_eq!(deterministic_f32_be_bytes(nan3), expected);
    }

    #[test]
    fn deterministic_f32_le_bytes_canonical_nan() {
        // Any NaN should map to canonical NaN in little-endian
        let nan = f32::from_bits(0x7fc0_0001);
        let expected = [0x00, 0x00, 0xc0, 0x7f]; // Canonical NaN in little-endian
        assert_eq!(deterministic_f32_le_bytes(nan), expected);
    }

    #[test]
    fn deterministic_f32_signed_zero_normalization() {
        // Both +0.0 and -0.0 should normalize to +0.0
        assert_eq!(
            deterministic_f32_be_bytes(0.0),
            deterministic_f32_be_bytes(-0.0)
        );
        assert_eq!(
            deterministic_f32_le_bytes(0.0),
            deterministic_f32_le_bytes(-0.0)
        );
        assert_eq!(deterministic_f32_be_bytes(0.0), [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(deterministic_f32_le_bytes(0.0), [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn deterministic_f64_be_bytes_canonical_nan() {
        // Any NaN should map to canonical NaN
        let nan1 = f64::from_bits(0x7ff8_0000_0000_0001); // Signaling NaN
        let nan2 = f64::from_bits(0x7ff0_1234_5678_9abc); // Quiet NaN with payload
        let nan3 = f64::NAN; // Standard NaN

        let expected = [0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // Canonical NaN in big-endian
        assert_eq!(deterministic_f64_be_bytes(nan1), expected);
        assert_eq!(deterministic_f64_be_bytes(nan2), expected);
        assert_eq!(deterministic_f64_be_bytes(nan3), expected);
    }

    #[test]
    fn deterministic_f64_le_bytes_canonical_nan() {
        // Any NaN should map to canonical NaN in little-endian
        let nan = f64::from_bits(0x7ff8_0000_0000_0001);
        let expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x7f]; // Canonical NaN in little-endian
        assert_eq!(deterministic_f64_le_bytes(nan), expected);
    }

    #[test]
    fn deterministic_f64_signed_zero_normalization() {
        // Both +0.0 and -0.0 should normalize to +0.0
        assert_eq!(
            deterministic_f64_be_bytes(0.0),
            deterministic_f64_be_bytes(-0.0)
        );
        assert_eq!(
            deterministic_f64_le_bytes(0.0),
            deterministic_f64_le_bytes(-0.0)
        );
        assert_eq!(deterministic_f64_be_bytes(0.0), [0x00; 8]);
        assert_eq!(deterministic_f64_le_bytes(0.0), [0x00; 8]);
    }

    #[test]
    fn deterministic_float_normal_values() {
        // Normal values should be unchanged
        let f32_val = std::f32::consts::PI;
        let f64_val = std::f64::consts::PI;

        assert_eq!(
            deterministic_f32_be_bytes(f32_val),
            f32_val.to_bits().to_be_bytes()
        );
        assert_eq!(
            deterministic_f32_le_bytes(f32_val),
            f32_val.to_bits().to_le_bytes()
        );
        assert_eq!(
            deterministic_f64_be_bytes(f64_val),
            f64_val.to_bits().to_be_bytes()
        );
        assert_eq!(
            deterministic_f64_le_bytes(f64_val),
            f64_val.to_bits().to_le_bytes()
        );
    }

    #[test]
    fn deterministic_float_infinities() {
        // Infinities should be unchanged
        assert_eq!(
            deterministic_f32_be_bytes(f32::INFINITY),
            f32::INFINITY.to_bits().to_be_bytes()
        );
        assert_eq!(
            deterministic_f32_be_bytes(f32::NEG_INFINITY),
            f32::NEG_INFINITY.to_bits().to_be_bytes()
        );
        assert_eq!(
            deterministic_f64_be_bytes(f64::INFINITY),
            f64::INFINITY.to_bits().to_be_bytes()
        );
        assert_eq!(
            deterministic_f64_be_bytes(f64::NEG_INFINITY),
            f64::NEG_INFINITY.to_bits().to_be_bytes()
        );
    }

    #[test]
    fn merkle_root_from_simple_graph() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        let _file_id = file.id.clone();
        graph.add_root(file).unwrap();

        let root = MerkleRoot::from_graph(&graph);

        // Adding same content should give same root
        let mut graph2 = ObjectGraph::new();
        let file2 = Object::file(b"test content".to_vec());
        graph2.add_root(file2).unwrap();
        let root2 = MerkleRoot::from_graph(&graph2);

        assert_eq!(root, root2);

        // Different content should give different root
        let mut graph3 = ObjectGraph::new();
        let file3 = Object::file(b"different content".to_vec());
        graph3.add_root(file3).unwrap();
        let root3 = MerkleRoot::from_graph(&graph3);

        assert_ne!(root, root3);
    }

    #[test]
    fn manifest_from_graph_works() {
        let mut graph = ObjectGraph::new();

        let file1 = Object::file(b"content1".to_vec());
        let file2 = Object::file(b"content2".to_vec());

        let file1_id = file1.id.clone();
        let file2_id = file2.id.clone();

        graph.add_root(file1).unwrap();
        graph.add_root(file2).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy.clone()).unwrap();

        assert_eq!(manifest.version, ManifestVersion::CURRENT);
        assert_eq!(manifest.metadata_policy, policy);
        assert_eq!(manifest.object_count(), 2);
        assert_eq!(manifest.roots.len(), 2);
        assert!(manifest.roots.contains(&file1_id));
        assert!(manifest.roots.contains(&file2_id));
        assert!(manifest.objects.contains_key(&file1_id));
        assert!(manifest.objects.contains_key(&file2_id));
    }

    #[test]
    fn manifest_validation_works() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        // Valid manifest should pass validation
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_validation_catches_missing_root() {
        let graph = ObjectGraph::new();
        let policy = MetadataPolicy::default();
        let mut manifest = Manifest::from_graph(&graph, policy).unwrap();

        // Add a root that doesn't exist in objects
        let missing_id = ObjectId::content(ContentId::from_bytes(b"missing-root"));
        manifest.roots.push(missing_id.clone());

        let result = manifest.validate();
        assert!(matches!(result, Err(ManifestError::RootObjectMissing(id)) if id == missing_id));
    }

    #[test]
    fn manifest_validation_rejects_overflowing_chunk_boundary() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test".to_vec());
        let file_id = file.id.clone();
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let mut manifest = Manifest::from_graph(&graph, policy).unwrap();

        // byte_offset + size_bytes wraps u64; the wrap must be rejected
        // instead of silently re-arming the ascending-order check.
        let obj = manifest.objects.get_mut(&file_id).unwrap();
        obj.chunk_boundaries = vec![ChunkBoundary {
            index: 0,
            byte_offset: u64::MAX - 1,
            size_bytes: 2,
            content_hash: [0u8; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: None,
        }];

        let result = manifest.validate();
        assert!(
            matches!(result, Err(ManifestError::InvalidFormat(ref msg)) if msg.contains("overflows")),
            "overflowing chunk boundary must be rejected, got {result:?}"
        );
    }

    #[test]
    fn commit_creation_and_validation_works() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        let metadata = CommitMetadata {
            timestamp_nanos: 1234567890,
            author: "test_author".to_string(),
            message: "test commit".to_string(),
        };

        let commit = GraphCommit::new(None, manifest, metadata);

        // Commit should validate successfully
        assert!(commit.validate().is_ok());
        assert!(commit.parent.is_none());
    }

    #[test]
    fn commit_with_parent_works() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        let metadata = CommitMetadata {
            timestamp_nanos: 1234567890,
            author: "test_author".to_string(),
            message: "test commit".to_string(),
        };

        let parent_id = CommitId::new([1; 32]);
        let commit = GraphCommit::new(Some(parent_id.clone()), manifest, metadata);

        assert_eq!(commit.parent, Some(parent_id));
        assert!(commit.validate().is_ok());
    }

    #[test]
    fn manifest_canonical_bytes_are_deterministic() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest1 = Manifest::from_graph(&graph, policy.clone()).unwrap();
        let manifest2 = Manifest::from_graph(&graph, policy).unwrap();

        let bytes1 = manifest1.to_canonical_bytes();
        let bytes2 = manifest2.to_canonical_bytes();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn commit_id_is_deterministic() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        let metadata = CommitMetadata {
            timestamp_nanos: 1234567890,
            author: "test_author".to_string(),
            message: "test commit".to_string(),
        };

        let id1 = CommitId::from_commit(&manifest, &metadata);
        let id2 = CommitId::from_commit(&manifest, &metadata);

        assert_eq!(id1, id2);
    }

    #[test]
    fn hash_algorithm_properties() {
        assert_eq!(HashAlgorithm::Sha256.hash_size(), 32);
        assert_eq!(HashAlgorithm::Blake3.hash_size(), 32);
        assert!(HashAlgorithm::Sha256.is_required());
        assert!(!HashAlgorithm::Blake3.is_required());
    }

    #[test]
    fn manifest_requires_sha256() {
        let graph = ObjectGraph::new();
        let policy = MetadataPolicy::default();

        // Should fail without SHA-256
        let result = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Blake3],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(matches!(result, Err(ManifestError::InvalidFormat(_))));
    }

    #[test]
    fn manifest_with_chunk_plan() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"large content for chunking".to_vec());
        graph.add_root(file).unwrap();

        let chunk_plan = ChunkPlan {
            strategy: ChunkStrategy::ContentDefined,
            target_chunk_size: 64 * 1024,
            min_chunk_size: 32 * 1024,
            max_chunk_size: 128 * 1024,
            cdc_params: Some(CdcParams {
                window_size: 64,
                average_chunk_size: 64 * 1024,
                normalization: 0x0001_0000,
            }),
        };

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256],
            Some(chunk_plan.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(manifest.chunk_plan.is_some());
        assert_eq!(
            manifest.chunk_plan.as_ref().unwrap().strategy,
            ChunkStrategy::ContentDefined
        );
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_with_raptorq_layout() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"content requiring FEC".to_vec());
        graph.add_root(file).unwrap();

        let raptorq_layout = RaptorQRepairLayout {
            source_symbols: 1000,
            total_symbols: 1200,
            symbol_size: 1024,
            overhead_ratio: 0.2,
            sub_blocks: vec![SubBlock {
                index: 0,
                source_symbols: 1000,
                esi_range: (0, 1199),
            }],
        };

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256],
            None,
            Some(raptorq_layout.clone()),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(manifest.raptorq_layout.is_some());
        assert_eq!(
            manifest.raptorq_layout.as_ref().unwrap().source_symbols,
            1000
        );
        assert_eq!(
            manifest.raptorq_layout.as_ref().unwrap().total_symbols,
            1200
        );
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_with_compression_policy() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"compressible content with lots of repetition".to_vec());
        graph.add_root(file).unwrap();

        let compression_policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 6,
            min_size_threshold: 1024,
            apply_to_kinds: vec![ObjectKind::FileObject, ObjectKind::DatasetObject],
        };

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256],
            None,
            None,
            Some(compression_policy.clone()),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(manifest.compression_policy.is_some());
        assert_eq!(
            manifest.compression_policy.as_ref().unwrap().algorithm,
            CompressionAlgorithm::Lz4
        );
        assert!(manifest.validate().is_ok());
    }

    #[test]
    #[cfg(feature = "compression")]
    fn manifest_computes_gzip_and_brotli_metadata_from_real_content() {
        for algorithm in [CompressionAlgorithm::Gzip, CompressionAlgorithm::Brotli] {
            let mut graph = ObjectGraph::new();
            let file = Object::file(
                b"manifest compression metadata metadata metadata chunk chunk chunk".repeat(8),
            );
            let object_id = file.id.clone();
            let object_size = file.metadata.size_bytes.unwrap();
            graph.add_root(file).unwrap();

            let compression_policy = CompressionPolicy {
                algorithm,
                level: 6,
                min_size_threshold: 1,
                apply_to_kinds: vec![ObjectKind::FileObject],
            };

            let manifest = Manifest::from_graph_with_policies(
                &graph,
                MetadataPolicy::default(),
                vec![HashAlgorithm::Sha256],
                None,
                None,
                Some(compression_policy),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            let metadata = manifest.objects[&object_id]
                .compression_metadata
                .as_ref()
                .expect("compression metadata should be computed from object content");
            assert_eq!(metadata.algorithm, algorithm);
            assert_eq!(metadata.original_size, object_size);
            assert!(metadata.compressed_size > 0);
            assert_eq!(
                metadata.compression_ratio,
                metadata.compressed_size as f32 / metadata.original_size as f32
            );
        }
    }

    #[test]
    fn manifest_with_encryption_policy() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"sensitive content requiring encryption".to_vec());
        graph.add_root(file).unwrap();

        let encryption_policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::Argon2id,
                salt: b"random_salt_32_bytes_long_example".to_vec(),
                iterations: Some(100_000),
            },
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256],
            None,
            None,
            None,
            Some(encryption_policy.clone()),
            None,
            None,
            None,
        )
        .unwrap();

        assert!(manifest.encryption_policy.is_some());
        assert_eq!(
            manifest.encryption_policy.as_ref().unwrap().algorithm,
            EncryptionAlgorithm::ChaCha20Poly1305
        );
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_with_capability_policy() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"authorized content".to_vec());
        graph.add_root(file).unwrap();

        let capability_policy = CapabilityPolicy {
            read_capabilities: vec!["read:public".to_string(), "read:authenticated".to_string()],
            write_capabilities: vec!["write:admin".to_string()],
            verify_capabilities: vec!["verify:trusted".to_string()],
            delegation_rules: vec![DelegationRule {
                capability: "read:public".to_string(),
                target: "user:*".to_string(),
                constraints: vec!["time:business_hours".to_string()],
                expires_at: Some(1_640_995_200_000_000_000), // 2022-01-01 00:00:00 UTC
            }],
        };

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256],
            None,
            None,
            None,
            None,
            Some(capability_policy.clone()),
            None,
            None,
        )
        .unwrap();

        assert!(manifest.capability_policy.is_some());
        assert_eq!(
            manifest
                .capability_policy
                .as_ref()
                .unwrap()
                .read_capabilities
                .len(),
            2
        );
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn chunk_plan_validation_errors() {
        let graph = ObjectGraph::new();
        let policy = MetadataPolicy::default();

        // Invalid chunk sizes
        let bad_chunk_plan = ChunkPlan {
            strategy: ChunkStrategy::FixedSize,
            target_chunk_size: 32 * 1024,
            min_chunk_size: 64 * 1024, // min > target
            max_chunk_size: 128 * 1024,
            cdc_params: None,
        };

        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy.clone(),
            vec![HashAlgorithm::Sha256],
            Some(bad_chunk_plan),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidFormat(_))
        ));

        // Content-defined without CDC params
        let bad_chunk_plan2 = ChunkPlan {
            strategy: ChunkStrategy::ContentDefined,
            target_chunk_size: 64 * 1024,
            min_chunk_size: 32 * 1024,
            max_chunk_size: 128 * 1024,
            cdc_params: None, // Missing for ContentDefined
        };

        let manifest2 = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256],
            Some(bad_chunk_plan2),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(matches!(
            manifest2.validate(),
            Err(ManifestError::InvalidFormat(_))
        ));
    }

    #[test]
    fn raptorq_layout_validation_errors() {
        let graph = ObjectGraph::new();
        let policy = MetadataPolicy::default();

        // Invalid RaptorQ layout
        let bad_layout = RaptorQRepairLayout {
            source_symbols: 1500,
            total_symbols: 1000, // total < source
            symbol_size: 1024,
            overhead_ratio: 0.2,
            sub_blocks: vec![],
        };

        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy.clone(),
            vec![HashAlgorithm::Sha256],
            None,
            Some(bad_layout),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidFormat(_))
        ));

        // Invalid overhead ratio
        let bad_layout2 = RaptorQRepairLayout {
            source_symbols: 1000,
            total_symbols: 1200,
            symbol_size: 1024,
            overhead_ratio: 1.5, // > 1.0
            sub_blocks: vec![],
        };

        let manifest2 = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256],
            None,
            Some(bad_layout2),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(matches!(
            manifest2.validate(),
            Err(ManifestError::InvalidFormat(_))
        ));
    }

    #[test]
    fn unknown_critical_field_validation() {
        let graph = ObjectGraph::new();
        let policy = MetadataPolicy::default();
        let mut manifest = Manifest::from_graph(&graph, policy).unwrap();

        // Add an unknown critical field
        manifest.unknown_optional_fields.push(UnknownField {
            name: "future_critical_feature".to_string(),
            field_type: FieldType::Critical,
            data: b"critical_data".to_vec(),
        });

        // Validation should fail for unknown critical fields
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::UnknownCriticalField(_))
        ));

        // But unknown optional fields should be ignored
        manifest.unknown_optional_fields[0].field_type = FieldType::Optional;
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_deterministic_across_policies() {
        let mut graph = ObjectGraph::new();
        let file1 = Object::file(b"content1".to_vec());
        let file2 = Object::file(b"content2".to_vec());
        graph.add_root(file1).unwrap();
        graph.add_object(file2).unwrap();

        let policy = MetadataPolicy::default();

        // Create identical manifests with same policies
        let manifest1 = Manifest::from_graph_with_policies(
            &graph,
            policy.clone(),
            vec![HashAlgorithm::Sha256, HashAlgorithm::Blake3],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let manifest2 = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256, HashAlgorithm::Blake3],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        // Merkle roots should be identical
        assert_eq!(manifest1.merkle_root, manifest2.merkle_root);

        // Canonical manifest metadata should be identical for identical graph inputs.
        assert_eq!(manifest1.objects, manifest2.objects);
        assert_eq!(manifest1.hash_algorithms, manifest2.hash_algorithms);
        assert_eq!(manifest1.schema_id, manifest2.schema_id);
    }

    #[test]
    fn manifest_with_all_policies_validates() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"comprehensive test content".to_vec());
        graph.add_root(file).unwrap();

        let chunk_plan = ChunkPlan {
            strategy: ChunkStrategy::ContentDefined,
            target_chunk_size: 64 * 1024,
            min_chunk_size: 32 * 1024,
            max_chunk_size: 128 * 1024,
            cdc_params: Some(CdcParams {
                window_size: 64,
                average_chunk_size: 64 * 1024,
                normalization: 0x0001_0000,
            }),
        };

        let raptorq_layout = RaptorQRepairLayout {
            source_symbols: 1000,
            total_symbols: 1200,
            symbol_size: 1024,
            overhead_ratio: 0.2,
            sub_blocks: vec![SubBlock {
                index: 0,
                source_symbols: 1000,
                esi_range: (0, 1199),
            }],
        };

        let compression_policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 6,
            min_size_threshold: 1024,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        let encryption_policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::Argon2id,
                salt: b"test_salt_32_bytes_long_example!".to_vec(),
                iterations: Some(100_000),
            },
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let capability_policy = CapabilityPolicy {
            read_capabilities: vec!["read:authenticated".to_string()],
            write_capabilities: vec!["write:admin".to_string()],
            verify_capabilities: vec!["verify:trusted".to_string()],
            delegation_rules: vec![],
        };

        // ATP-C4 transform policies
        let transform_order = TransformOrder {
            transforms: vec![
                TransformType::Chunking,
                TransformType::Compression,
                TransformType::Encryption,
                TransformType::ErrorCorrection,
            ],
            hash_point: HashPoint::MultiPoint,
            verification_boundary: VerificationBoundary {
                relay_verifiable: VerificationLevel::TransferIntegrity,
                mailbox_verifiable: VerificationLevel::ContentHash,
                e2e_verification_required: true,
                privacy_level: PrivacyLevel::MetadataVisible,
            },
        };

        let transform_proof_policy = TransformProofPolicy {
            enforce_transform_order: true,
            require_deterministic_transforms: true,
            allow_lossy_transforms: false,
            require_plaintext_hash: true,
            max_compression_ratio: Some(10.0),
            encryption_domains: vec![EncryptionDomain {
                domain_id: "secure".to_string(),
                allowed_kdfs: vec![KeyDerivationFunction::Argon2id],
                relay_privacy: true,
                mailbox_privacy: true,
            }],
            minimum_proof_strength: ProofStrength::Enhanced,
        };

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph_with_policies(
            &graph,
            policy,
            vec![HashAlgorithm::Sha256, HashAlgorithm::Blake3],
            Some(chunk_plan),
            Some(raptorq_layout),
            Some(compression_policy),
            Some(encryption_policy),
            Some(capability_policy),
            Some(transform_order),
            Some(transform_proof_policy),
        )
        .unwrap();

        // Comprehensive validation should pass
        assert!(manifest.validate().is_ok());

        // All policies should be present
        assert!(manifest.chunk_plan.is_some());
        assert!(manifest.raptorq_layout.is_some());
        assert!(manifest.compression_policy.is_some());
        assert!(manifest.encryption_policy.is_some());
        assert!(manifest.capability_policy.is_some());
        assert!(manifest.transform_order.is_some());
        assert!(manifest.transform_proof_policy.is_some());
        assert_eq!(manifest.hash_algorithms.len(), 2);

        // ATP-C4 specific validations
        let transform_order = manifest.transform_order.as_ref().unwrap();
        assert_eq!(transform_order.transforms.len(), 4);
        assert!(
            transform_order
                .transforms
                .contains(&TransformType::Compression)
        );
        assert!(
            transform_order
                .transforms
                .contains(&TransformType::Encryption)
        );
        assert_eq!(transform_order.hash_point, HashPoint::MultiPoint);

        let proof_policy = manifest.transform_proof_policy.as_ref().unwrap();
        assert!(proof_policy.enforce_transform_order);
        assert!(proof_policy.require_deterministic_transforms);
        assert!(!proof_policy.allow_lossy_transforms);
        assert!(proof_policy.require_plaintext_hash);

        // Canonical serialization should be deterministic
        let bytes = manifest.to_canonical_bytes();
        assert!(bytes.starts_with(b"ATPM")); // Magic header
        assert!(bytes.len() > 100); // Should be substantial with all policies

        // Should have proper schema ID
        assert_eq!(manifest.schema_id, "atp.manifest.v1");
    }

    mod atp_g2_tests {
        use super::*;
        use crate::atp::object::{ContentId, Object, ObjectGraph};
        use std::collections::BTreeMap;

        /// Create a test repair group for validation testing.
        fn create_test_repair_group(object_id: ObjectId) -> RepairGroup {
            let group_id = RepairGroupId::new(&object_id, 0, 1024);

            RepairGroup {
                group_id: group_id.clone(),
                object_id: object_id.clone(),
                source_block_number: 0,
                chunk_range: ChunkRange {
                    start_chunk: 0,
                    end_chunk: 10,
                    start_offset: 0,
                    end_offset: 10240,
                },
                source_symbols_k: 1000,
                k_prime: 1024,
                symbol_size: 1024,
                repair_layout: RepairLayout {
                    total_repair_symbols: 200,
                    overhead_ratio: 0.2,
                    systematic_config: SystematicConfig {
                        systematic_rows: 1000,
                        sub_symbols: 1,
                        alignment: 8,
                    },
                    interleaving: InterleavingPattern {
                        block_size: 1,
                        depth: 1,
                        pattern_type: InterleavingType::None,
                    },
                },
                hash_domain: HashDomain {
                    domain_id: "test-domain".to_string(),
                    hash_algorithm: HashAlgorithm::Sha256,
                    context: b"test-context".to_vec(),
                },
                transform_policy: None,
                auth_domain: AuthenticationDomain {
                    domain_id: "test-auth-domain".to_string(),
                    required_proof_strength: ProofStrength::Basic,
                    auth_algorithm: AuthenticationAlgorithm::HmacSha256,
                    peer_identity_required: false,
                    transfer_identity_binding: true,
                    session_binding: true,
                },
                capability_policy: None,
                manifest_root: MerkleRoot::new([0u8; 32]),
            }
        }

        /// Create a test manifest with repair groups.
        fn create_test_manifest_with_repair_groups() -> Manifest {
            let mut graph = ObjectGraph::new();
            let object = Object::file(vec![0u8; 10240]);
            let object_id = object.id.clone();
            graph.add_object(object).unwrap();

            // Create manifest with repair group
            let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
            let mut repair_group = create_test_repair_group(object_id.clone());
            repair_group.manifest_root = manifest.merkle_root.clone();
            let group_id = repair_group.group_id.clone();
            manifest
                .repair_groups
                .insert(group_id.clone(), repair_group);

            // Add symbols to the manifest object referencing the repair group
            if let Some(manifest_obj) = manifest.objects.get_mut(&object_id) {
                manifest_obj.raptorq_symbols = vec![
                    RaptorQSymbol {
                        index: 0,
                        esi: 0,
                        size_bytes: 1024,
                        content_hash: [1u8; 32],
                        is_source: true,
                        repair_group_id: Some(group_id.clone()),
                        auth_tag: None,
                    },
                    RaptorQSymbol {
                        index: 1,
                        esi: 1000,
                        size_bytes: 1024,
                        content_hash: [3u8; 32],
                        is_source: false,
                        repair_group_id: Some(group_id),
                        auth_tag: None,
                    },
                ];
            }
            manifest.merkle_root = MerkleRoot::from_manifest_components(
                &manifest.objects,
                &manifest.chunk_plan,
                &manifest.raptorq_layout,
                &manifest.compression_policy,
                &manifest.encryption_policy,
                &manifest.capability_policy,
                &manifest.transform_order,
                &manifest.transform_proof_policy,
                &manifest.repair_groups,
            );
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.manifest_root = manifest.merkle_root.clone();
            }
            Manifest::bind_repair_symbol_auth_tags(&mut manifest.objects, &manifest.repair_groups);

            manifest
        }

        #[test]
        fn test_repair_group_id_generation() {
            let object_id = ObjectId::content(ContentId::new([1u8; 32]));
            let group_id1 = RepairGroupId::new(&object_id, 0, 1024);
            let group_id2 = RepairGroupId::new(&object_id, 0, 1024);
            let group_id3 = RepairGroupId::new(&object_id, 1, 1024);

            // Same parameters should produce same ID
            assert_eq!(group_id1, group_id2);

            // Different source block should produce different ID
            assert_ne!(group_id1, group_id3);

            // ID should be 16 bytes
            assert_eq!(group_id1.as_bytes().len(), 16);
        }

        #[test]
        fn test_repair_group_validation_success() {
            let manifest = create_test_manifest_with_repair_groups();

            // Should validate successfully
            let result = manifest.validate();
            assert!(result.is_ok(), "Validation failed: {:?}", result);
        }

        #[test]
        fn test_repair_group_validation_invalid_group_id() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Corrupt the group ID in the repair group
            let wrong_object_id = ObjectId::content(ContentId::new([99u8; 32]));
            let correct_group_id = RepairGroupId::new(&wrong_object_id, 0, 1024);

            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.group_id = correct_group_id; // Wrong ID for this repair group
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));
        }

        #[test]
        fn test_repair_group_validation_k_prime_constraint() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Make K' < K (invalid)
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.k_prime = 500; // Less than source_symbols_k (1000)
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));
        }

        #[test]
        fn test_repair_group_validation_symbol_reference_error() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Add a symbol that references a non-existent repair group
            let missing_group_id =
                RepairGroupId::new(&ObjectId::content(ContentId::new([99u8; 32])), 99, 999);

            if let Some(manifest_obj) = manifest.objects.values_mut().next() {
                manifest_obj.raptorq_symbols.push(RaptorQSymbol {
                    index: 99,
                    esi: 1001,
                    size_bytes: 1024,
                    content_hash: [5u8; 32],
                    is_source: false,
                    repair_group_id: Some(missing_group_id),
                    auth_tag: Some([6u8; 32]),
                });
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupReferenceError(_))
            ));
        }

        #[test]
        fn test_repair_group_validation_missing_auth_tag() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Remove auth tag from a symbol that has repair group ID
            if let Some(manifest_obj) = manifest.objects.values_mut().next() {
                if let Some(symbol) = manifest_obj.raptorq_symbols.get_mut(0) {
                    symbol.auth_tag = None;
                }
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupAuthenticationError(_))
            ));
        }

        #[test]
        fn test_repair_group_validation_chunk_range_errors() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Invalid chunk range (end <= start)
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.chunk_range.end_chunk = repair_group.chunk_range.start_chunk;
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));
        }

        #[test]
        fn test_repair_group_validation_zero_symbol_size() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Zero symbol size should fail
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.symbol_size = 0;
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));
        }

        #[test]
        fn test_repair_group_validation_overhead_ratio_bounds() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Overhead ratio out of bounds (negative)
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.repair_layout.overhead_ratio = -0.1;
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));

            // Fix and try too large overhead ratio
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.repair_layout.overhead_ratio = 15.0; // > 10.0 max
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));
        }

        #[test]
        fn test_repair_group_validation_empty_domain_id() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Empty authentication domain ID
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.auth_domain.domain_id.clear();
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));
        }

        #[test]
        fn test_repair_group_manifest_root_binding() {
            let mut manifest = create_test_manifest_with_repair_groups();

            // Manifest root mismatch
            if let Some(repair_group) = manifest.repair_groups.values_mut().next() {
                repair_group.manifest_root = MerkleRoot::new([99u8; 32]);
            }

            let result = manifest.validate();
            assert!(matches!(
                result,
                Err(ManifestError::RepairGroupValidationError(_))
            ));
        }

        #[test]
        fn test_merkle_root_includes_repair_groups() {
            let manifest = create_test_manifest_with_repair_groups();

            // Compute root with repair groups
            let root_with_groups = MerkleRoot::from_manifest_components(
                &manifest.objects,
                &manifest.chunk_plan,
                &manifest.raptorq_layout,
                &manifest.compression_policy,
                &manifest.encryption_policy,
                &manifest.capability_policy,
                &manifest.transform_order,
                &manifest.transform_proof_policy,
                &manifest.repair_groups,
            );

            // Compute root without repair groups
            let root_without_groups = MerkleRoot::from_manifest_components(
                &manifest.objects,
                &manifest.chunk_plan,
                &manifest.raptorq_layout,
                &manifest.compression_policy,
                &manifest.encryption_policy,
                &manifest.capability_policy,
                &manifest.transform_order,
                &manifest.transform_proof_policy,
                &BTreeMap::new(),
            );

            // Roots should be different when repair groups are included
            assert_ne!(root_with_groups, root_without_groups);

            // The manifest's computed root should match the one with repair groups
            let computed_manifest_root = MerkleRoot::from_manifest_components(
                &manifest.objects,
                &manifest.chunk_plan,
                &manifest.raptorq_layout,
                &manifest.compression_policy,
                &manifest.encryption_policy,
                &manifest.capability_policy,
                &manifest.transform_order,
                &manifest.transform_proof_policy,
                &manifest.repair_groups,
            );

            // Should match since validate() passes
            assert_eq!(manifest.merkle_root, computed_manifest_root);
        }

        #[test]
        fn test_repair_group_interleaving_pattern_hashing() {
            let object_id = ObjectId::content(ContentId::new([1u8; 32]));

            // Test different interleaving patterns produce different hashes
            let mut repair_group1 = create_test_repair_group(object_id.clone());
            repair_group1.repair_layout.interleaving.pattern_type = InterleavingType::None;

            let mut repair_group2 = repair_group1.clone();
            repair_group2.repair_layout.interleaving.pattern_type = InterleavingType::Block;

            let mut repair_group3 = repair_group1.clone();
            repair_group3.repair_layout.interleaving.pattern_type =
                InterleavingType::Randomized(12345);

            let groups1 = {
                let mut map = BTreeMap::new();
                map.insert(repair_group1.group_id.clone(), repair_group1);
                map
            };

            let groups2 = {
                let mut map = BTreeMap::new();
                map.insert(repair_group2.group_id.clone(), repair_group2);
                map
            };

            let groups3 = {
                let mut map = BTreeMap::new();
                map.insert(repair_group3.group_id.clone(), repair_group3);
                map
            };

            let root1 = MerkleRoot::from_manifest_components(
                &BTreeMap::new(),
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &groups1,
            );

            let root2 = MerkleRoot::from_manifest_components(
                &BTreeMap::new(),
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &groups2,
            );

            let root3 = MerkleRoot::from_manifest_components(
                &BTreeMap::new(),
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &groups3,
            );

            // All should be different
            assert_ne!(root1, root2);
            assert_ne!(root1, root3);
            assert_ne!(root2, root3);
        }
    }
