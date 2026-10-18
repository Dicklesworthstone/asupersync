    use super::*;
    use crate::net::atp::transport_common::DeltaChunkWire;
    use super::super::ManifestEntry;

    fn fixture(size: u64) -> (TransferManifest, DeltaManifestWire) {
        let entry = ManifestEntry {
            index: 0,
            rel_path: "payload".into(),
            size,
            sha256_hex: "00".repeat(32),
            metadata: None,
            members: Vec::new(),
        };
        let delta = DeltaManifestWire {
            schema: "schema".into(),
            tree_id: "33".repeat(32),
            chunk_size: 4096,
            total_size_bytes: size,
            merkle_root_hex: "11".repeat(32),
            chunks: if size == 0 {
                Vec::new()
            } else {
                vec![DeltaChunkWire {
                    index: 0,
                    entry_index: 0,
                    rel_path: "payload".into(),
                    entry_offset: 0,
                    stream_offset: 0,
                    size_bytes: size,
                    content_id_hex: "22".repeat(32),
                }]
            },
        };
        (
            TransferManifest {
                transfer_id: "t".into(),
                root_name: "r".into(),
                is_directory: false,
                total_bytes: size,
                merkle_root_hex: "33".repeat(32),
                metadata_root_hex: None,
                directory_metadata: None,
                entries: vec![entry],
                delta_manifest: Some(delta.clone()),
            },
            delta,
        )
    }

    #[test]
    fn accepts_complete_bounded_layout() {
        let (manifest, delta) = fixture(1024);
        validate(&manifest, &delta).unwrap();
        let (manifest, delta) = fixture(0);
        validate(&manifest, &delta).unwrap();
    }

    #[test]
    fn rejects_unbounded_chunk_size_before_baseline_reads() {
        let (manifest, mut delta) = fixture(1);
        delta.chunk_size = usize::try_from(MAX_COMPRESSED_CHUNK_RAW).unwrap() + 1;
        assert!(validate(&manifest, &delta).is_err());
        delta.chunk_size = 0;
        assert!(validate(&manifest, &delta).is_err());
    }

    #[test]
    fn rejects_path_index_and_extent_mismatches() {
        let (manifest, delta) = fixture(10);
        for mutate in 0..4 {
            let mut bad = delta.clone();
            match mutate {
                0 => bad.chunks[0].entry_index = 7,
                1 => bad.chunks[0].rel_path = "other".into(),
                2 => bad.chunks[0].entry_offset = 1,
                _ => bad.chunks[0].size_bytes = 11,
            }
            assert!(validate(&manifest, &bad).is_err(), "case {mutate}");
        }
    }

    #[test]
    fn rejects_partial_coverage_and_transfer_total_mismatch() {
        let (manifest, mut delta) = fixture(10);
        delta.chunks[0].size_bytes = 9;
        assert!(validate(&manifest, &delta).is_err());

        let (manifest, mut delta) = fixture(10);
        delta.total_size_bytes = 9;
        assert!(validate(&manifest, &delta).is_err());
    }

    #[test]
    fn rejects_content_for_metadata_only_entries() {
        let (mut manifest, delta) = fixture(10);
        manifest.entries[0].metadata = Some(EntryMetadata {
            file_kind: FileKind::Directory,
            ..EntryMetadata::default()
        });
        assert!(validate(&manifest, &delta).is_err());
    }

// These fixtures use the same independent content and planner commitments as
// the native TCP sender, not invented roots or a substitute delta planner.
fn committed_single_file(bytes: &[u8]) -> TransferManifest {
    use crate::atp::delta::{CasChunkRef, PersistentChunkManifest};
    use crate::atp::object::{ContentId, ObjectId};
    use crate::net::atp::transport_common::{EntryDigest, flat_merkle_root_from_digests};
    use sha2::{Digest, Sha256};

    let size = u64::try_from(bytes.len()).expect("test payload size");
    assert!(size <= 16, "one-chunk test fixture");
    let content_sha256: [u8; 32] = Sha256::digest(bytes).into();
    let content_id = ContentId::from_bytes(bytes);
    let root = flat_merkle_root_from_digests(&[EntryDigest {
        rel_path: "payload".into(),
        size,
        content_id: ObjectId::content(content_id.clone()),
        content_sha256,
    }]);
    let chunks = if bytes.is_empty() {
        Vec::new()
    } else {
        vec![CasChunkRef {
            index: 0,
            byte_offset: 0,
            size_bytes: size,
            content_id: content_id.clone(),
        }]
    };
    let planner = PersistentChunkManifest::new(root.clone(), chunks)
        .expect("real canonical planner manifest");
    TransferManifest {
        transfer_id: "bindingtest".into(),
        root_name: "payload".into(),
        is_directory: false,
        total_bytes: size,
        merkle_root_hex: root.clone(),
        metadata_root_hex: None,
        directory_metadata: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: "payload".into(),
            size,
            sha256_hex: crate::net::atp::transport_common::hex_encode(&content_sha256),
            metadata: None,
            members: Vec::new(),
        }],
        delta_manifest: Some(DeltaManifestWire {
            schema: super::super::ATP_DELTA_CHUNK_MANIFEST_SCHEMA.into(),
            tree_id: root,
            chunk_size: 16,
            total_size_bytes: size,
            merkle_root_hex: planner.merkle_root.to_hex(),
            chunks: if bytes.is_empty() {
                Vec::new()
            } else {
                vec![DeltaChunkWire {
                    index: 0,
                    entry_index: 0,
                    rel_path: "payload".into(),
                    entry_offset: 0,
                    stream_offset: 0,
                    size_bytes: size,
                    content_id_hex: content_id.to_hex(),
                }]
            },
        }),
    }
}

#[test]
fn a_self_consistent_delta_plan_must_commit_to_the_enclosing_content_root() {
    let old = committed_single_file(b"old payload");
    let mut wanted = committed_single_file(b"new payload");
    assert_eq!(old.total_bytes, wanted.total_bytes);
    assert_ne!(old.merkle_root_hex, wanted.merkle_root_hex);
    wanted.delta_manifest = old.delta_manifest;
    let delta = wanted.delta_manifest.as_ref().expect("replayed delta plan");

    // This is not a corrupt delta root: the real planner accepts it. The
    // missing gate was the link between two individually valid commitments.
    super::super::planner_manifest_from_wire(delta).expect("self-consistent old plan");
    assert!(matches!(
        validate(&wanted, delta),
        Err(TransportError::Frame(message)) if message.contains("transfer content root")
    ));
}

#[test]
fn receiver_negotiation_cannot_noop_new_content_with_a_replayed_old_delta_plan() {
    use super::super::{DeltaWireMode, TransferConfig, build_receiver_delta_state};
    use crate::atp::object::MetadataPolicy;

    let directory = tempfile::tempdir().expect("receiver destination");
    let destination = directory.path().canonicalize().expect("canonical destination");
    std::fs::write(destination.join("payload"), b"old payload").expect("existing file");
    let old = committed_single_file(b"old payload");
    let wanted = committed_single_file(b"new payload");
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let config = TransferConfig {
            chunk_size: 16,
            metadata_policy: MetadataPolicy::portable(),
            ..TransferConfig::default()
        };
        let unchanged = build_receiver_delta_state(&destination, &old, &config)
            .await
            .expect("real unchanged-file baseline");
        assert_eq!(unchanged.request.mode, DeltaWireMode::AlreadyInSync);
        let changed = build_receiver_delta_state(&destination, &wanted, &config)
            .await
            .expect("real changed-file baseline");
        assert_ne!(changed.request.mode, DeltaWireMode::AlreadyInSync);

        let mut replayed = wanted;
        replayed.delta_manifest = old.delta_manifest;
        let rejected = build_receiver_delta_state(&destination, &replayed, &config).await;
        assert!(matches!(
            rejected,
            Err(TransportError::Frame(message)) if message.contains("transfer content root")
        ));
        assert_eq!(std::fs::read(destination.join("payload")).unwrap(), b"old payload");
    }));
}

#[test]
fn commitment_mismatch_is_rejected_even_when_delta_reuse_is_disabled() {
    use super::super::{TransferConfig, build_receiver_delta_state};

    let directory = tempfile::tempdir().expect("test root");
    let missing = directory.path().join("not-created");
    let old = committed_single_file(b"old payload");
    let mut wanted = committed_single_file(b"new payload");
    wanted.delta_manifest = old.delta_manifest;
    let config = TransferConfig {
        enable_delta: false,
        ..TransferConfig::default()
    };
    let refused = futures_lite::future::block_on(build_receiver_delta_state(
        &missing, &wanted, &config,
    ));
    assert!(matches!(
        refused,
        Err(TransportError::Frame(message)) if message.contains("transfer content root")
    ));
    assert!(!missing.exists(), "preflight must not create a destination");
}
