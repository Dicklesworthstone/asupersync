    use super::*;
    use crate::atp::actor::{TransferActorId, TransferActorTopology, TransferRegionId};
    use crate::atp::manifest::MerkleRoot;
    use crate::atp::object::ContentId;
    use crate::atp::stream_object::EpochState;
    use crate::atp::sync::{
        DirectoryEarlyUsabilityState, DirectoryEntryKind, DirectoryEntryMetadata,
        DirectoryManifestEntry, DirectoryPath, PathNormalizationRules,
    };
    use crate::atp::transfer::{PeerCapabilities, TransferManifestRef};
    use crate::cx::{Cx, cap};
    use crate::types::{Budget, RegionId, TaskId};
    use std::collections::BTreeSet;
    use std::time::{Duration, SystemTime};

    fn test_cx() -> Cx<cap::All> {
        Cx::new(
            RegionId::new_for_test(0, 1),
            TaskId::testing_default(),
            Budget::INFINITE,
        )
    }

    #[test]
    fn sdk_legacy_mod_examples_are_executable_assertions() {
        let source = include_str!("sdk/mod.rs");
        let examples = source
            .split("mod examples")
            .nth(1)
            .expect("legacy SDK examples module exists");

        for (forbidden, label) in [
            (concat!("#[", "ignore", "]"), "ignored test attribute"),
            (concat!("#[", "tokio::test", "]"), "tokio test attribute"),
            (concat!("to", "do", "!("), "deferred macro"),
            (concat!("un", "implemented", "!("), "unsupported macro"),
            (concat!("println", "!("), "stdout print macro"),
            ("would transfer", "print-only transfer wording"),
            ("would stream", "print-only stream wording"),
        ] {
            assert!(
                !examples.contains(forbidden),
                "legacy SDK example module still contains non-executable marker {label}"
            );
        }

        for required in [
            "fn example_write_really_big_buffer_asserts_transfer_shape()",
            "fn example_stream_unknown_size_asserts_chunk_sequence()",
            "assert_eq!(chunks.len()",
            "assert_eq!(total_bytes",
        ] {
            assert!(
                examples.contains(required),
                "legacy SDK example module is missing executable assertion marker {required:?}"
            );
        }
    }

    fn registry_actor(transfer_id: TransferId) -> TransferActorHandle {
        Arc::new(ContendedMutex::new(
            "atp_transfer_actor",
            TransferActor::new(
                TransferActorId::new(1),
                transfer_id,
                TransferManifestRef {
                    schema_version: 1,
                    merkle_root: [9; 32],
                    object_count: 1,
                },
                PeerCapabilities::default(),
                TransferActorTopology::new(TransferRegionId::new(10), TransferRegionId::new(20)),
            )
            .unwrap(),
        ))
    }

    fn directory_file(path: &str, content_id: &str, size_bytes: u64) -> DirectoryManifestEntry {
        DirectoryManifestEntry::new(
            DirectoryPath::normalize(path, PathNormalizationRules::default()).unwrap(),
            DirectoryEntryKind::File,
            Some(content_id.to_string()),
            DirectoryEntryMetadata {
                size_bytes: Some(size_bytes),
                ..DirectoryEntryMetadata::default()
            },
        )
    }

    fn directory_manifest(entries: Vec<DirectoryManifestEntry>) -> DirectoryManifest {
        let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
        for entry in entries {
            manifest.insert(entry).unwrap();
        }
        manifest
    }

    #[test]
    fn test_atp_config_defaults() {
        let config = AtpConfig::default();
        assert_eq!(config.target_chunk_size, 64 * 1024);
        assert_eq!(config.max_concurrent_transfers, 8);
        assert!(config.in_process);
        assert!(config.enable_diagnostics);
    }

    #[test]
    fn test_transfer_handle_creation() {
        let transfer_id = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);
        let handle = TransferHandle {
            transfer_id,
            session_id: "test-session".to_string(),
            direction: TransferDirection::Send,
            actor: Some(registry_actor(transfer_id)),
        };

        assert_eq!(handle.transfer_id, transfer_id);
        assert_eq!(handle.session_id, "test-session");
        assert_eq!(handle.direction, TransferDirection::Send);
        assert_eq!(handle.state(), TransferState::Offered);
    }

    #[test]
    fn transfer_handle_progress_measures_verified_against_offered() {
        // Regression (br-asupersync-bi2462.53): progress() previously computed
        // bytes_transferred as max(committed, verified, offered). The actor
        // reports offered >= verified >= committed, so that always collapsed to
        // offered_bytes — every transfer reported 100% the instant it offered
        // bytes, before a single byte was verified or committed.
        let transfer_id = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);
        let handle = TransferHandle {
            transfer_id,
            session_id: "test-session".to_string(),
            direction: TransferDirection::Send,
            actor: Some(registry_actor(transfer_id)),
        };
        {
            let actor = handle.actor.as_ref().unwrap();
            actor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .progress = crate::atp::transfer::TransferProgress {
                offered_bytes: 1_000,
                verified_bytes: 400,
                committed_bytes: 200,
                ..Default::default()
            };
        }

        let progress = handle.progress();
        assert_eq!(
            progress.total_bytes, 1_000,
            "total is the offered denominator"
        );
        assert_eq!(
            progress.bytes_transferred, 400,
            "verified bytes are transferred; offered bytes are not"
        );
        assert!(
            (progress.progress_percent - 40.0).abs() < 1e-9,
            "expected 40% verified of the offered total, got {}",
            progress.progress_percent
        );
    }

    #[test]
    fn transfer_handle_progress_reaches_full_only_when_verified() {
        let transfer_id = TransferId::derive([5; 32], [6; 32], [7; 32], [8; 32]);
        let handle = TransferHandle {
            transfer_id,
            session_id: "s".to_string(),
            direction: TransferDirection::Receive,
            actor: Some(registry_actor(transfer_id)),
        };
        {
            let actor = handle.actor.as_ref().unwrap();
            actor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .progress = crate::atp::transfer::TransferProgress {
                offered_bytes: 1_000,
                verified_bytes: 1_000,
                committed_bytes: 1_000,
                ..Default::default()
            };
        }
        let progress = handle.progress();
        assert_eq!(progress.bytes_transferred, 1_000);
        assert_eq!(progress.total_bytes, 1_000);
        assert!((progress.progress_percent - 100.0).abs() < 1e-9);
    }

    #[test]
    fn transfer_registry_shards_distinct_transfer_ids() {
        let registry = TransferRegistry::new(4);
        let shard_indexes: BTreeSet<_> = (0_u8..4)
            .map(|prefix| {
                let mut bytes = [0_u8; 32];
                bytes[0] = prefix;
                registry.shard_for(TransferId::new(bytes))
            })
            .collect();

        assert_eq!(shard_indexes.len(), 4);
    }

    #[test]
    fn transfer_cancel_removes_actor_before_taking_actor_lock() {
        let registry = TransferRegistry::new(4);
        let transfer_id = TransferId::new([7; 32]);
        let actor = registry_actor(transfer_id);

        registry.insert(
            transfer_id,
            TransferRegistryEntry {
                actor: actor.clone(),
                direction: TransferDirection::Send,
                object_id: None,
            },
        );
        assert_eq!(registry.len(), 1);

        let removed = registry.remove(transfer_id).unwrap();
        assert_eq!(registry.len(), 0);

        request_transfer_cancel(&removed.actor);
        let actor = actor.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(actor.state(), TransferState::Cancelling);
    }

    #[test]
    fn transfer_cancel_key_is_bound_to_transfer_id() {
        let first_id = TransferId::new([11; 32]);
        let second_id = TransferId::new([12; 32]);
        let first_actor = registry_actor(first_id);
        let second_actor = registry_actor(second_id);

        request_transfer_cancel(&first_actor);
        request_transfer_cancel(&second_actor);

        let first_actor = first_actor.lock().unwrap_or_else(PoisonError::into_inner);
        let second_actor = second_actor.lock().unwrap_or_else(PoisonError::into_inner);
        let first_key = first_actor.journal()[0].key;
        let second_key = second_actor.journal()[0].key;

        assert_ne!(first_key, IdempotencyKey::new(0));
        assert_ne!(second_key, IdempotencyKey::new(0));
        assert_ne!(first_key, second_key);
    }

    #[test]
    fn transfer_cancel_key_is_stable_for_duplicate_cancel() {
        let transfer_id = TransferId::new([13; 32]);
        let actor = registry_actor(transfer_id);

        request_transfer_cancel(&actor);
        request_transfer_cancel(&actor);

        let actor = actor.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(actor.state(), TransferState::Cancelling);
        assert_eq!(actor.journal().len(), 1);
        assert_eq!(actor.journal()[0].key, cancel_idempotency_key(transfer_id));
    }

    #[test]
    fn transfer_close_drains_all_shards_before_cancelling_actors() {
        let registry = TransferRegistry::new(8);
        for prefix in 0_u8..8 {
            let mut bytes = [0_u8; 32];
            bytes[0] = prefix;
            let transfer_id = TransferId::new(bytes);
            registry.insert(
                transfer_id,
                TransferRegistryEntry {
                    actor: registry_actor(transfer_id),
                    direction: TransferDirection::Send,
                    object_id: None,
                },
            );
        }

        let drained = registry.drain();
        assert_eq!(drained.len(), 8);
        assert_eq!(registry.len(), 0);

        for entry in &drained {
            request_transfer_cancel(&entry.actor);
        }
        for entry in drained {
            let actor = entry.actor.lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(actor.state(), TransferState::Cancelling);
        }
    }

    #[test]
    fn test_stream_handle_progress() {
        let handle = StreamHandle {
            stream_id: "test-stream".to_string(),
            total_bytes: 1000,
            bytes_sent: 250,
            manifest: None,
        };

        assert!(!handle.is_complete());
        assert_eq!(handle.progress_percent(), 25.0);
    }

    #[test]
    fn test_stream_handle_completion() {
        let handle = StreamHandle {
            stream_id: "test-stream".to_string(),
            total_bytes: 1000,
            bytes_sent: 1000,
            manifest: None,
        };

        assert!(handle.is_complete());
        assert_eq!(handle.progress_percent(), 100.0);
    }

    #[test]
    fn directory_handle_report_surfaces_sdk_metadata_and_small_files() {
        let manifest = directory_manifest(vec![
            directory_file("docs/README.md", "readme-cid", 512),
            directory_file("model.bin", "model-cid", 4 * 1024 * 1024),
        ]);
        let mut handle = DirectoryHandle::new("sdk-directory", manifest);

        assert!(handle.mark_content_verified("readme-cid"));
        assert!(handle.mark_content_verified("model-cid"));
        assert_eq!(handle.verified_content_count(), 2);

        let report = handle.early_usability_report(
            DirectoryEarlyUsabilityPolicy::small_files_up_to(1024),
            "sdk-directory-replay:small-files",
        );

        assert_eq!(
            report.usability_state,
            DirectoryEarlyUsabilityState::SmallFilesAvailable
        );
        assert_eq!(
            report.final_commit_state,
            DirectoryFinalCommitState::Pending
        );
        assert_eq!(report.replay_pointer, "sdk-directory-replay:small-files");
        assert_eq!(report.metadata_paths, vec!["docs/README.md", "model.bin"]);
        assert_eq!(report.small_file_paths, vec!["docs/README.md"]);
        assert_eq!(report.withheld_content_paths, vec!["model.bin"]);
        assert!(report.safety_caveats.contains(
            &"final directory commit not complete; expose early entries separately".to_string()
        ));
    }

    #[test]
    fn directory_handle_report_keeps_final_commit_state_separate() {
        let manifest = directory_manifest(vec![directory_file("done.txt", "done-cid", 32)]);
        let mut handle = DirectoryHandle::new("sdk-directory-final", manifest);
        let policy = DirectoryEarlyUsabilityPolicy {
            expose_metadata_before_final: false,
            ..DirectoryEarlyUsabilityPolicy::small_files_up_to(1024)
        };

        let pending = handle.early_usability_report(policy, "sdk-directory-replay:pending");
        assert_eq!(
            pending.usability_state,
            DirectoryEarlyUsabilityState::NoEntries
        );
        assert_eq!(
            pending.final_commit_state,
            DirectoryFinalCommitState::Pending
        );
        assert!(pending.metadata_paths.is_empty());
        assert!(pending.small_file_paths.is_empty());
        assert!(
            pending.safety_caveats.contains(
                &"metadata exposure is disabled until final directory commit".to_string()
            )
        );

        handle.mark_final_committed();
        assert!(handle.is_final_committed());

        let committed = handle.early_usability_report(policy, "sdk-directory-replay:committed");
        assert_eq!(
            committed.usability_state,
            DirectoryEarlyUsabilityState::FinalCommitted
        );
        assert_eq!(
            committed.final_commit_state,
            DirectoryFinalCommitState::Committed
        );
        assert_eq!(committed.metadata_paths, vec!["done.txt"]);
        assert_eq!(committed.small_file_paths, vec!["done.txt"]);
        assert!(committed.safety_caveats.is_empty());
    }

    #[test]
    fn stream_handle_report_disables_early_use_without_manifest() {
        let handle = StreamHandle {
            stream_id: "stream-no-manifest".to_string(),
            total_bytes: 1000,
            bytes_sent: 250,
            manifest: None,
        };

        let report = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);

        assert_eq!(report.usable_state, StreamEarlyUsabilityState::NoManifest);
        assert_eq!(
            report.final_commit_state,
            StreamFinalCommitState::UnknownNoManifest
        );
        assert!(report.verified_prefix_ranges.is_empty());
        assert_eq!(report.policy_exposed_prefix, None);
        assert_eq!(report.verified_prefix_end, 0);
        assert_eq!(report.policy_prefix_end, 0);
        assert!(
            report
                .safety_caveats
                .contains(&"stream manifest unavailable; early usability is disabled".to_string())
        );
    }

    #[test]
    fn stream_handle_report_separates_verified_prefix_from_provisional_policy_tail() {
        let object_id = ObjectId::content(ContentId::new([3; 32]));
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id,
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let handle = StreamHandle {
            stream_id: "stream-provisional-tail".to_string(),
            total_bytes: 300,
            bytes_sent: 200,
            manifest: Some(manifest),
        };

        let verified_only = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);
        assert_eq!(
            verified_only.usable_state,
            StreamEarlyUsabilityState::VerifiedPrefixAvailable
        );
        assert_eq!(
            verified_only.final_commit_state,
            StreamFinalCommitState::Pending
        );
        assert_eq!(
            verified_only.verified_prefix_ranges,
            vec![ByteRange::new(0, 100)]
        );
        assert_eq!(
            verified_only.policy_exposed_prefix,
            Some(ByteRange::new(0, 100))
        );
        assert_eq!(verified_only.verified_prefix_end, 100);
        assert_eq!(verified_only.policy_prefix_end, 100);

        let provisional = handle.early_usability_report(ConsumptionPolicy::AllowProvisional);
        assert_eq!(
            provisional.usable_state,
            StreamEarlyUsabilityState::ProvisionalPrefixAvailable
        );
        assert_eq!(
            provisional.verified_prefix_ranges,
            vec![ByteRange::new(0, 100)]
        );
        assert_eq!(
            provisional.policy_exposed_prefix,
            Some(ByteRange::new(0, 200))
        );
        assert_eq!(provisional.verified_prefix_end, 100);
        assert_eq!(provisional.policy_prefix_end, 200);
        assert!(
            provisional.safety_caveats.contains(
                &"provisional tail is exposed by policy and may be invalidated".to_string()
            )
        );
    }

    #[test]
    fn stream_handle_report_withholds_verified_epochs_after_invalidated_gap() {
        let object_id = ObjectId::content(ContentId::new([4; 32]));
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Invalidated,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let handle = StreamHandle {
            stream_id: "stream-gap".to_string(),
            total_bytes: 300,
            bytes_sent: 300,
            manifest: Some(manifest),
        };

        let report = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);

        assert_eq!(
            report.usable_state,
            StreamEarlyUsabilityState::VerifiedPrefixAvailable
        );
        assert_eq!(report.verified_prefix_ranges, vec![ByteRange::new(0, 100)]);
        assert_eq!(report.policy_exposed_prefix, Some(ByteRange::new(0, 100)));
        assert!(report.safety_caveats.contains(
            &"verified epochs after a gap or non-consumable epoch are withheld".to_string()
        ));
    }

    #[test]
    fn stream_handle_report_marks_final_commit_separately() {
        let object_id = ObjectId::content(ContentId::new([5; 32]));
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id,
                ByteRange::new(0, 100),
                EpochState::Final,
                vec![],
            ))
            .unwrap();

        let handle = StreamHandle {
            stream_id: "stream-final".to_string(),
            total_bytes: 100,
            bytes_sent: 100,
            manifest: Some(manifest),
        };

        let report = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);

        assert_eq!(
            report.usable_state,
            StreamEarlyUsabilityState::FinalCommitted
        );
        assert_eq!(report.final_commit_state, StreamFinalCommitState::Committed);
        assert_eq!(report.verified_prefix_ranges, vec![ByteRange::new(0, 100)]);
        assert_eq!(report.policy_exposed_prefix, Some(ByteRange::new(0, 100)));
        assert!(report.safety_caveats.is_empty());
    }

    #[test]
    fn test_atp_session_lifecycle() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let config = AtpConfig::default();

            // Open session
            let session = AtpSession::open(cx, config).await.unwrap();
            assert!(matches!(
                session.session_id.strip_prefix("atp-session-"),
                Some(nonce) if nonce.len() == 32
                    && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
            ));
            assert_ne!(session.local_peer_id, [0u8; 32]); // Should not be all zeros

            // Close session
            session.close(cx).await.unwrap();
        });
    }

    fn is_feature_refusal<T>(outcome: &AtpOutcome<T>) -> bool {
        matches!(
            outcome,
            Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
        )
    }

    #[test]
    fn legacy_session_refuses_transfers_and_verdicts_it_cannot_produce() {
        // asupersync-bi2462.127: each call used to succeed, or return a verdict,
        // without I/O. The session has no transport and no object store.
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [2u8; 32];
            let object_id = ObjectId::content(ContentId::new([1u8; 32]));

            assert!(is_feature_refusal(
                &session
                    .send_object(cx, object_id.clone(), remote_peer)
                    .await
            ));
            assert_eq!(session.active_transfers.len(), 0, "no transfer registered");
            assert!(is_feature_refusal(
                &session
                    .stream_large_buffer(cx, b"payload", remote_peer)
                    .await
            ));
            // The id's own hash as the expected hash used to report verified.
            assert!(is_feature_refusal(
                &session
                    .verify_object(cx, object_id.clone(), Some(*object_id.hash_bytes()))
                    .await
            ));
            assert!(is_feature_refusal(
                &session.verify_object(cx, object_id, None).await
            ));
            assert!(is_feature_refusal(
                &session.path_diagnose(cx, remote_peer).await
            ));
        });
    }

    #[test]
    fn cancel_transfer_cancels_a_held_transfer_once_and_refuses_unknown_ids() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let unknown = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);
            assert!(matches!(
                session.cancel_transfer(cx, unknown).await,
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
            ));

            let held = TransferId::from_u128(7);
            let actor = registry_actor(held);
            session.active_transfers.insert(
                held,
                TransferRegistryEntry {
                    actor: Arc::clone(&actor),
                    direction: TransferDirection::Send,
                    object_id: None,
                },
            );
            session.cancel_transfer(cx, held).await.unwrap();
            assert_eq!(
                actor.lock().unwrap_or_else(PoisonError::into_inner).state(),
                TransferState::Cancelling
            );
            assert!(matches!(
                session.cancel_transfer(cx, held).await,
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
            ));
        });
    }

    #[test]
    fn stream_consumer_reads_a_final_verified_manifest() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let object_id = ObjectId::content(ContentId::new([3; 32]));
            let mut manifest = StreamManifest::new(object_id.clone());
            manifest
                .add_epoch(StreamEpoch::new(
                    1,
                    object_id,
                    ByteRange::new(0, 64),
                    EpochState::Final,
                    vec![],
                ))
                .unwrap();

            let consumer = session
                .create_stream_consumer(manifest, ConsumptionPolicy::VerifiedOnly)
                .unwrap();

            assert!(consumer.data_available());
        });
    }

    #[test]
    fn test_stream_epochs_retrieval() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let object_id = ObjectId::content(ContentId::new([1u8; 32]));

            assert!(matches!(
                session.get_stream_epochs(cx, object_id).await,
                Outcome::Err(AtpError::Manifest(ManifestError::ObjectNotFound))
            ));
        });
    }

    #[test]
    fn test_write_buffer_ergonomic_api() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [3u8; 32];
            let data = b"This is the write(really_big_buffer) test!".repeat(1000);

            // Refuses rather than fabricate a TransferProof without transport (asupersync-txa7vi)
            let result = session
                .write_buffer(cx, &data, remote_peer, None)
                .await;

            assert!(is_feature_refusal(&result));
        });
    }

    #[test]
    fn test_create_writer_with_progress() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [4u8; 32];

            // Create writer with custom config
            let mut writer_config = WriterConfig::default();
            writer_config.enable_progress = true;
            writer_config.chunk_size = 1024;

            let result = session.create_writer(remote_peer, Some(writer_config));
            assert!(is_feature_refusal(&result));
        });
    }

    #[test]
    fn test_sink_api() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [5u8; 32];

            let result = session.create_sink(remote_peer, None);
            assert!(is_feature_refusal(&result));
        });
    }

    #[test]
    fn test_resume_functionality() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [6u8; 32];

            let token = ResumeToken {
                transfer_id: TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]),
                object_id: ObjectId::content(ContentId::new([1; 32])),
                verified_bytes: 1024,
                manifest_root: MerkleRoot::zero(),
                journal_position: 1024,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            };

            let result = session.resume_writer(token, remote_peer, None);
            assert!(is_feature_refusal(&result));
        });
    }

    #[test]
    fn test_stream_writer_unknown_size() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [7u8; 32];

            let result = session
                .create_stream_writer(cx, remote_peer, None)
                .await;
            assert!(is_feature_refusal(&result));
        });
    }

    #[test]
    fn test_object_graph_sending() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [8u8; 32];

            let root_object = ObjectId::content(ContentId::new([42u8; 32]));

            assert!(matches!(
                session
                    .send_object_graph(cx, root_object, remote_peer, None)
                    .await,
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
            ));
        });
    }

    /// Test that ensures fabricated values are not returned in real APIs.
    /// This checks for the SDK integrity issues mentioned in the bead.
    #[test]
    fn test_no_mock_values_in_real_implementation() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [1u8; 32]; // Non-zero peer
            let object_id = ObjectId::content(ContentId::new([1u8; 32])); // Non-zero object

            // 1. Check that session peer ID is not all zeros
            assert_ne!(
                session.local_peer_id, [0u8; 32],
                "Session peer ID should not be all zeros"
            );

            // 2. send_object refuses rather than hand out a handle for a transfer
            // that moves nothing (asupersync-bi2462.127).
            assert!(is_feature_refusal(
                &session
                    .send_object(cx, object_id.clone(), remote_peer)
                    .await
            ));

            // 3. receive_object must not fabricate a receipt for an unknown transfer.
            let transfer_id =
                TransferId::derive(session.local_peer_id, remote_peer, [5; 32], [6; 32]);
            assert!(matches!(
                session.receive_object(cx, transfer_id).await,
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
            ));

            // 4. verify_object cannot read content, so it gives no verdict.
            assert!(is_feature_refusal(
                &session
                    .verify_object(cx, object_id.clone(), Some(*object_id.hash_bytes()))
                    .await
            ));

            // 5. Object graph sending must fail closed rather than synthesize bytes.
            let root_object = ObjectId::content(ContentId::new([99u8; 32]));
            assert!(matches!(
                session
                    .send_object_graph(cx, root_object, remote_peer, None)
                    .await,
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
            ));

            // 6. write_buffer, write_file, create_writer, create_sink, and
            // create_stream_writer refuse rather than fabricate a TransferProof (asupersync-txa7vi).
            assert!(is_feature_refusal(
                &session
                    .write_buffer(cx, b"payload", remote_peer, None)
                    .await
            ));
            assert!(is_feature_refusal(
                &session
                    .write_file(cx, "dummy/path", remote_peer, None)
                    .await
            ));
            assert!(is_feature_refusal(
                &session.create_writer(remote_peer, None)
            ));
            assert!(is_feature_refusal(
                &session.create_sink(remote_peer, None)
            ));
            assert!(is_feature_refusal(
                &session
                    .create_stream_writer(cx, remote_peer, None)
                    .await
            ));
        });
    }
