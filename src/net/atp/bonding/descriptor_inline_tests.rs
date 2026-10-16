    use super::*;
    use crate::atp::object::{ContentId, ObjectId};
    use crate::net::atp::transport_common::metadata::{
        SymlinkTargetInfo, SymlinkTargetKind, SymlinkTargetSemantics,
    };
    use crate::net::atp::transport_common::{
        DirectoryMetadataEntry, DirectoryMetadataManifest, EntryMetadata,
    };
    use crate::net::atp::transport_rq::{RqMetadataEntry, RqMetadataManifest};
    use sha2::{Digest, Sha256};

    fn sha_hex(bytes: &[u8]) -> String {
        let sha: [u8; 32] = Sha256::digest(bytes).into();
        hex_encode(&sha)
    }

    fn digest_for(rel_path: &str, bytes: &[u8]) -> EntryDigest {
        EntryDigest {
            rel_path: rel_path.to_string(),
            size: bytes.len() as u64,
            content_id: ObjectId::content(ContentId::from_bytes(bytes)),
            content_sha256: Sha256::digest(bytes).into(),
        }
    }

    fn descriptor_for(files: &[(u32, &str, &[u8])]) -> BondTransferDescriptor {
        let digests: Vec<EntryDigest> = files.iter().map(|(_, p, b)| digest_for(p, b)).collect();
        let entries: Vec<BondEntry> = files
            .iter()
            .map(|(i, p, b)| BondEntry {
                index: *i,
                rel_path: (*p).to_string(),
                size: b.len() as u64,
                sha256_hex: sha_hex(b),
            })
            .collect();
        let total: u64 = files.iter().map(|(_, _, b)| b.len() as u64).sum();
        BondTransferDescriptor {
            transfer_id: "tid-deadbeef".to_string(),
            root_name: "root".to_string(),
            is_directory: files.len() != 1,
            total_bytes: total,
            merkle_root_hex: flat_merkle_root_from_digests(&digests),
            metadata: None,
            entries,
            symbol_size: 1200,
            max_block_size: 8 << 20,
            auth_key_id: Some("key-1".to_string()),
        }
    }

    const FILES: &[(u32, &str, &[u8])] = &[
        (0, "a.bin", b"hello bonded world"),
        (1, "sub/b.bin", b"second donor file"),
    ];

    #[test]
    fn verify_local_digests_accepts_a_byte_identical_copy() {
        let desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();
        assert!(desc.verify_local_digests(&digests).is_ok());
    }

    #[test]
    fn donation_proof_token_requires_byte_identical_local_digests() {
        let desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();

        let proof = desc
            .prove_local_digests_for_donation(&digests)
            .expect("byte-identical donor proof");

        assert_eq!(proof.transfer_id, desc.transfer_id);
        assert_eq!(proof.merkle_root_hex, desc.merkle_root_hex);
        assert_eq!(proof.total_bytes, desc.total_bytes);
        assert_eq!(proof.entry_count, desc.entries.len());
    }

    #[test]
    fn traced_donation_proof_accepts_matching_local_digests() {
        let desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();

        let proof = desc
            .prove_local_digests_for_donation_traced(&digests)
            .expect("byte-identical donor proof");

        assert_eq!(proof.transfer_id, desc.transfer_id);
        assert_eq!(proof.merkle_root_hex, desc.merkle_root_hex);
    }

    #[test]
    fn traced_donation_proof_refuses_tampered_copy_with_merkle_evidence() {
        let desc = descriptor_for(FILES);
        let digests = vec![
            digest_for("a.bin", b"HELLO bonded world"),
            digest_for("sub/b.bin", b"second donor file"),
        ];
        let recomputed = flat_merkle_root_from_digests(&digests);

        let trace = desc
            .prove_local_digests_for_donation_traced(&digests)
            .expect_err("tampered donor copy must refuse before spray");

        assert_eq!(trace.schema_version, BONDING_DONOR_REFUSAL_TRACE_SCHEMA);
        assert_eq!(trace.event, "bonding_donor_refused");
        assert_eq!(trace.transfer_id, desc.transfer_id);
        assert_eq!(trace.expected_merkle_root_hex, desc.merkle_root_hex);
        assert_eq!(trace.recomputed_merkle_root_hex, Some(recomputed));
        assert_ne!(
            trace.recomputed_merkle_root_hex.as_deref(),
            Some(desc.merkle_root_hex.as_str())
        );
        assert_eq!(trace.refusal_code, "entry_mismatch");
        assert_eq!(trace.entry_rel_path.as_deref(), Some("a.bin"));
        assert_eq!(trace.descriptor_entry_count, desc.entries.len());
        assert_eq!(trace.local_digest_count, digests.len());

        let json = serde_json::to_value(&trace).expect("refusal trace serializes");
        assert_eq!(
            json["schema_version"].as_str(),
            Some(BONDING_DONOR_REFUSAL_TRACE_SCHEMA)
        );
        assert_eq!(json["event"].as_str(), Some("bonding_donor_refused"));
        assert_eq!(json["refusal_code"].as_str(), Some("entry_mismatch"));
    }

    #[test]
    fn donation_proof_token_refuses_descriptor_merkle_drift() {
        let mut desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();
        let forged_root = "00".repeat(32);
        desc.merkle_root_hex = forged_root.clone();

        assert!(matches!(
            desc.prove_local_digests_for_donation(&digests),
            Err(BondProofError::MerkleMismatch {
                expected,
                recomputed,
            }) if expected == forged_root && recomputed != expected
        ));
    }

    #[test]
    fn donation_proof_token_refuses_tampered_local_digests() {
        let desc = descriptor_for(FILES);
        let digests = vec![
            digest_for("a.bin", b"HELLO bonded world"),
            digest_for("sub/b.bin", b"second donor file"),
        ];

        assert_eq!(
            desc.prove_local_digests_for_donation(&digests),
            Err(BondProofError::EntryMismatch {
                rel_path: "a.bin".to_string(),
            })
        );
    }

    #[test]
    fn descriptor_validate_rejects_duplicate_index_path_and_bad_total() {
        let desc = descriptor_for(FILES);
        desc.validate().expect("baseline descriptor");

        let mut duplicate_index = desc.clone();
        duplicate_index.entries[1].index = duplicate_index.entries[0].index;
        assert!(matches!(
            duplicate_index.validate().unwrap_err(),
            BondProofError::DuplicateEntryIndex { .. }
        ));

        let mut duplicate_path = desc.clone();
        duplicate_path.entries[1].rel_path = duplicate_path.entries[0].rel_path.clone();
        assert!(matches!(
            duplicate_path.validate().unwrap_err(),
            BondProofError::DuplicateEntryPath { .. }
        ));

        let mut unsafe_path = desc.clone();
        unsafe_path.entries[0].rel_path = "../escape".to_string();
        assert!(matches!(
            unsafe_path.verify_local_digests(&[]).unwrap_err(),
            BondProofError::UnsafePath { .. }
        ));

        let mut absolute_path = desc.clone();
        absolute_path.entries[0].rel_path = "/abs/path".to_string();
        assert!(matches!(
            absolute_path.verify_local_digests(&[]).unwrap_err(),
            BondProofError::UnsafePath { .. }
        ));

        let mut bad_total = desc;
        bad_total.total_bytes += 1;
        assert!(matches!(
            bad_total.verify_local_digests(&[]).unwrap_err(),
            BondProofError::TotalBytesMismatch { .. }
        ));
    }

    #[test]
    fn verify_local_digests_rejects_a_tampered_entry() {
        let desc = descriptor_for(FILES);
        // Flip the first entry's bytes: per-entry SHA-256 disagrees → refuse.
        let digests = vec![
            digest_for("a.bin", b"HELLO bonded world"),
            digest_for("sub/b.bin", b"second donor file"),
        ];
        assert!(matches!(
            desc.verify_local_digests(&digests).unwrap_err(),
            BondProofError::EntryMismatch { .. }
        ));
    }

    #[test]
    fn verify_local_digests_rejects_a_missing_entry() {
        let desc = descriptor_for(FILES);
        let digests = vec![digest_for("sub/b.bin", b"second donor file")];
        assert!(matches!(
            desc.verify_local_digests(&digests).unwrap_err(),
            BondProofError::MissingEntry { .. }
        ));
    }

    #[test]
    fn identical_bytes_produce_equal_descriptors_and_agree() {
        let a = descriptor_for(FILES);
        let b = descriptor_for(FILES);
        assert_eq!(a, b);
        assert!(a.agrees_with(&b));

        let different = descriptor_for(&[
            (0, "a.bin", b"HELLO bonded world"),
            (1, "sub/b.bin", b"second donor file"),
        ]);
        assert!(!a.agrees_with(&different), "different bytes must not agree");
    }

    #[test]
    fn descriptor_serde_round_trips() {
        let mut desc = descriptor_for(FILES);
        desc.metadata = Some(RqMetadataManifest {
            version: 1,
            commitment_hex: "44".repeat(32),
            entries: vec![RqMetadataEntry {
                rel_path: "a.bin".to_string(),
                metadata: EntryMetadata {
                    unix_mode: Some(0o640),
                    ..EntryMetadata::default()
                },
            }],
            directories: None,
        });
        let json = serde_json::to_string(&desc).expect("serialize");
        let back: BondTransferDescriptor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(desc, back);
    }

    #[test]
    fn entry_object_id_matches_the_rq_transport_derivation() {
        let desc = descriptor_for(FILES);
        let first = desc.entry_object_id(0);

        assert_eq!(first, desc.entry_object_id(0));
        assert_eq!(
            first,
            crate::net::atp::channel_bonding::entry_object_id(&desc.transfer_id, 0)
        );
        assert_eq!(first, bonded_entry_object_id(&desc.transfer_id, 0));
        assert_ne!(first, desc.entry_object_id(1));
        assert_ne!(first, bonded_entry_object_id("different-transfer", 0));
    }

    #[test]
    fn entry_block_geometry_locks_actual_per_block_k() {
        let mut desc = descriptor_for(&[(7, "payload.bin", b"0123456789abc")]);
        desc.symbol_size = 4;
        desc.max_block_size = 6;

        assert_eq!(desc.entry_source_block_count(7), Some(3));

        let first = desc.entry_block_geometry(7, 0).expect("first block");
        assert_eq!(first.entry_index, 7);
        assert_eq!(first.object_id, desc.entry_object_id(7));
        assert_eq!(first.source_block_number, 0);
        assert_eq!(first.source_block_count, 3);
        assert_eq!(first.block_start, 0);
        assert_eq!(first.block_bytes, 6);
        assert_eq!(first.source_symbols, 2);

        let second = desc.entry_block_geometry(7, 1).expect("second block");
        assert_eq!(second.block_start, 6);
        assert_eq!(second.block_bytes, 6);
        assert_eq!(second.source_symbols, 2);

        let final_partial = desc.entry_block_geometry(7, 2).expect("partial block");
        assert_eq!(final_partial.block_start, 12);
        assert_eq!(final_partial.block_bytes, 1);
        assert_eq!(final_partial.source_symbols, 1);

        assert!(desc.entry_block_geometry(7, 3).is_none());
        assert!(desc.entry_block_geometry(99, 0).is_none());
    }

    #[test]
    fn empty_entries_have_no_source_block_geometry() {
        let desc = descriptor_for(&[(0, "empty.bin", b"")]);
        assert_eq!(desc.entry_source_block_count(0), Some(0));
        assert!(desc.entry_block_geometry(0, 0).is_none());
    }

    #[test]
    fn bonded_topology_local_holding_verifies_hardlink_identity_without_hashing_alias() {
        let mut desc =
            descriptor_for(&[(0, "a-primary.bin", b"same inode"), (1, "b-alias.bin", b"")]);
        desc.metadata = Some(RqMetadataManifest {
            version: 1,
            commitment_hex: "55".repeat(32),
            entries: vec![RqMetadataEntry {
                rel_path: "b-alias.bin".to_string(),
                metadata: EntryMetadata {
                    hardlink_target: Some("a-primary.bin".to_string()),
                    ..EntryMetadata::default()
                },
            }],
            directories: None,
        });

        let linked = tempfile::tempdir().expect("linked donor root");
        std::fs::write(linked.path().join("a-primary.bin"), b"same inode")
            .expect("write hardlink primary");
        std::fs::hard_link(
            linked.path().join("a-primary.bin"),
            linked.path().join("b-alias.bin"),
        )
        .expect("create hardlink alias");
        futures_lite::future::block_on(desc.prove_local_holding(linked.path()))
            .expect("matching hardlink topology proves local holding");

        let independent = tempfile::tempdir().expect("independent donor root");
        std::fs::write(independent.path().join("a-primary.bin"), b"same inode")
            .expect("write independent primary");
        std::fs::write(independent.path().join("b-alias.bin"), b"same inode")
            .expect("write independent alias bytes");
        assert_eq!(
            futures_lite::future::block_on(desc.prove_local_holding(independent.path())),
            Err(BondProofError::EntryMismatch {
                rel_path: "b-alias.bin".to_string(),
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn bonded_topology_local_holding_verifies_relative_and_dangling_symlink_targets() {
        use std::os::unix::fs::symlink;

        let mut desc = descriptor_for(&[
            (0, "a-primary.bin", b"target bytes"),
            (1, "b-link.bin", b""),
            (2, "c-dangling.bin", b""),
        ]);
        desc.metadata = Some(RqMetadataManifest {
            version: 1,
            commitment_hex: "66".repeat(32),
            entries: vec![
                RqMetadataEntry {
                    rel_path: "b-link.bin".to_string(),
                    metadata: EntryMetadata {
                        file_kind: FileKind::Symlink,
                        symlink_target: Some("a-primary.bin".to_string()),
                        symlink_target_info: Some(SymlinkTargetInfo {
                            kind: Some(SymlinkTargetKind::File),
                            semantics: SymlinkTargetSemantics::PortableRelative,
                        }),
                        ..EntryMetadata::default()
                    },
                },
                RqMetadataEntry {
                    rel_path: "c-dangling.bin".to_string(),
                    metadata: EntryMetadata {
                        file_kind: FileKind::Symlink,
                        symlink_target: Some("missing.bin".to_string()),
                        symlink_target_info: Some(SymlinkTargetInfo {
                            kind: None,
                            semantics: SymlinkTargetSemantics::PortableRelative,
                        }),
                        ..EntryMetadata::default()
                    },
                },
            ],
            directories: None,
        });

        let matching = tempfile::tempdir().expect("matching symlink donor root");
        std::fs::write(matching.path().join("a-primary.bin"), b"target bytes")
            .expect("write symlink target");
        symlink("a-primary.bin", matching.path().join("b-link.bin"))
            .expect("create relative symlink");
        symlink("missing.bin", matching.path().join("c-dangling.bin"))
            .expect("create dangling symlink");
        futures_lite::future::block_on(desc.prove_local_holding(matching.path()))
            .expect("matching symlink topology proves local holding");

        let drifted = tempfile::tempdir().expect("drifted symlink donor root");
        std::fs::write(drifted.path().join("a-primary.bin"), b"target bytes")
            .expect("write expected target");
        std::fs::write(drifted.path().join("other.bin"), b"target bytes")
            .expect("write drifted target");
        symlink("other.bin", drifted.path().join("b-link.bin"))
            .expect("create drifted relative symlink");
        symlink("missing.bin", drifted.path().join("c-dangling.bin"))
            .expect("create dangling symlink");
        assert_eq!(
            futures_lite::future::block_on(desc.prove_local_holding(drifted.path())),
            Err(BondProofError::EntryMismatch {
                rel_path: "b-link.bin".to_string(),
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn bonded_topology_local_holding_rejects_a_symlink_in_place_of_an_empty_directory() {
        use std::os::unix::fs::symlink;

        let mut desc = descriptor_for(&[(0, "empty-dir", b"")]);
        desc.metadata = Some(RqMetadataManifest {
            version: 1,
            commitment_hex: "77".repeat(32),
            entries: Vec::new(),
            directories: Some(DirectoryMetadataManifest {
                root: None,
                entries: vec![DirectoryMetadataEntry {
                    rel_path: "empty-dir".to_string(),
                    metadata: EntryMetadata {
                        file_kind: FileKind::Directory,
                        ..EntryMetadata::default()
                    },
                }],
            }),
        });

        let donor = tempfile::tempdir().expect("directory donor root");
        std::fs::create_dir(donor.path().join("actual-dir")).expect("create actual directory");
        symlink("actual-dir", donor.path().join("empty-dir")).expect("create directory symlink");
        assert_eq!(
            futures_lite::future::block_on(desc.prove_local_holding(donor.path())),
            Err(BondProofError::EntryMismatch {
                rel_path: "empty-dir".to_string(),
            })
        );
    }

    #[test]
    fn entry_block_geometry_clamps_zero_symbol_and_block_inputs() {
        let mut desc = descriptor_for(&[(2, "payload.bin", b"abc")]);
        desc.symbol_size = 0;
        desc.max_block_size = 0;

        assert_eq!(desc.entry_source_block_count(2), Some(3));

        let first = desc.entry_block_geometry(2, 0).expect("first byte block");
        assert_eq!(first.block_start, 0);
        assert_eq!(first.block_bytes, 1);
        assert_eq!(first.source_symbols, 1);

        let final_block = desc.entry_block_geometry(2, 2).expect("final byte block");
        assert_eq!(final_block.block_start, 2);
        assert_eq!(final_block.block_bytes, 1);
        assert_eq!(final_block.source_symbols, 1);
        assert_eq!(final_block.source_block_count, 3);
        assert!(desc.entry_block_geometry(2, 3).is_none());
    }

    #[test]
    fn from_manifest_carries_every_agreed_field() {
        let metadata = RqMetadataManifest {
            version: 1,
            commitment_hex: "11".repeat(32),
            entries: vec![RqMetadataEntry {
                rel_path: "a.bin".to_string(),
                metadata: EntryMetadata {
                    mtime_unix_secs: Some(123),
                    mtime_nanos: Some(456),
                    ..EntryMetadata::default()
                },
            }],
            directories: None,
        };
        let manifest = TransferManifest {
            transfer_id: "tid-deadbeef".to_string(),
            root_name: "root".to_string(),
            is_directory: true,
            total_bytes: 18,
            merkle_root_hex: "abc123".to_string(),
            metadata: Some(metadata.clone()),
            delta_manifest: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a.bin".to_string(),
                size: 18,
                sha256_hex: "00ff".to_string(),
                members: Vec::new(),
                fragment: None,
            }],
        };
        let desc = BondTransferDescriptor::from_manifest(
            &manifest,
            1200,
            8 << 20,
            Some("key-1".to_string()),
        );
        assert_eq!(desc.transfer_id, "tid-deadbeef");
        assert_eq!(desc.merkle_root_hex, "abc123");
        assert_eq!(desc.symbol_size, 1200);
        assert_eq!(desc.max_block_size, 8 << 20);
        assert_eq!(desc.metadata, Some(metadata));
        assert_eq!(desc.entries.len(), 1);
        assert_eq!(desc.entries[0].rel_path, "a.bin");
        assert_eq!(desc.entries[0].sha256_hex, "00ff");
        assert_eq!(desc.auth_key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn metadata_commitment_participates_in_donor_agreement() {
        let mut first = descriptor_for(FILES);
        first.metadata = Some(RqMetadataManifest {
            version: 1,
            commitment_hex: "22".repeat(32),
            entries: Vec::new(),
            directories: None,
        });
        let mut second = first.clone();
        second.metadata.as_mut().expect("metadata").commitment_hex = "33".repeat(32);

        assert!(!first.agrees_with(&second));
    }

    #[test]
    fn safe_entry_path_rejects_traversal_and_absolute() {
        let root = Path::new("/tmp/donor-root");
        assert!(safe_entry_path(root, "a/b.bin").is_some());
        assert!(safe_entry_path(root, "../escape").is_none());
        assert!(safe_entry_path(root, "a/../../escape").is_none());
        assert!(safe_entry_path(root, "/abs/path").is_none());
        assert!(safe_entry_path(root, "").is_none());
    }
