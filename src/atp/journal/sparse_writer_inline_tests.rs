    use super::*;
    use crate::atp::manifest::Manifest;
    use crate::atp::object::ContentId;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};

    fn create_test_cx() -> Cx {
        Cx::for_testing()
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(label.as_bytes()))
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "asupersync_sparse_writer_{label}_{}_{}",
            std::process::id(),
            nanos
        ))
    }

    fn manifest_for_content(content: &[u8]) -> (ObjectId, Manifest) {
        let object = Object::file(content.to_vec());
        let object_id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph
            .add_root(object)
            .expect("test object graph should build");
        let manifest = Manifest::from_graph(&graph, MetadataPolicy::portable())
            .expect("manifest should build");
        (object_id, manifest)
    }

    #[test]
    fn test_sparse_writer_basic() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-object");
            let temp_dir = std::env::temp_dir();
            let final_path = temp_dir.join("test_sparse_output");

            let config = SparseWriterConfig::default();
            let writer = SparseWriter::new(&cx, object_id, final_path, config)
                .await
                .unwrap();

            // Set expected size
            writer.set_expected_size(1000).unwrap();

            // Write some chunks out of order
            let options = WriteOptions::default();
            writer
                .write_chunk(&cx, 500, b"middle", options.clone())
                .await
                .unwrap();
            writer
                .write_chunk(&cx, 0, b"start", options.clone())
                .await
                .unwrap();
            writer.write_chunk(&cx, 994, b"end", options).await.unwrap();

            // Check completion status
            assert!(!writer.is_complete()); // Still has gaps

            // Fill remaining gaps
            let fill_data = vec![0u8; 495];
            writer
                .write_chunk(&cx, 5, &fill_data, WriteOptions::default())
                .await
                .unwrap();
            let middle_fill = vec![0u8; 488];
            writer
                .write_chunk(&cx, 506, &middle_fill, WriteOptions::default())
                .await
                .unwrap();
            let end_fill = vec![0u8; 3];
            writer
                .write_chunk(&cx, 997, &end_fill, WriteOptions::default())
                .await
                .unwrap();

            assert!(writer.is_complete());
        });
    }

    #[test]
    fn out_of_object_writes_leave_file_and_progress_unchanged() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"abcdefgh";
            let (object_id, manifest) = manifest_for_content(content);
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("range_rejection"),
                SparseWriterConfig {
                    enable_preallocation: false,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            writer.set_expected_size(8).unwrap();

            for offset in [7, 8, 9] {
                assert!(matches!(
                    writer
                        .write_chunk(&cx, offset, b"xx", WriteOptions::default())
                        .await,
                    Outcome::Err(SparseWriterError::InvalidRange { .. })
                ));
                let state = writer.lock_state();
                assert!(state.temp_file.is_none());
                assert!(state.temp_path.is_none());
                assert!(state.written_chunks.is_empty());
            }

            writer
                .write_chunk(&cx, 0, &content[..4], WriteOptions::default())
                .await
                .unwrap();
            assert!(matches!(
                writer
                    .write_chunk(&cx, 7, b"xx", WriteOptions::default())
                    .await,
                Outcome::Err(SparseWriterError::InvalidRange { .. })
            ));
            let temp_path = writer.lock_state().temp_path.clone().unwrap();
            assert_eq!(std::fs::read(&temp_path).unwrap(), &content[..4]);
            assert_eq!(writer.get_stats().total_bytes_written, 4);
            assert_eq!(writer.get_stats().chunk_count, 1);

            // A rejected write must not prevent an exact-end write or verification.
            writer
                .write_chunk(&cx, 4, &content[4..], WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            writer.verify(&cx, &manifest).await.unwrap();
            assert_eq!(std::fs::read(&temp_path).unwrap(), content);
        });
    }

    #[test]
    fn expected_size_cannot_exclude_previously_written_bytes() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let writer = SparseWriter::new(
                &cx,
                test_object_id("resize-boundary"),
                unique_temp_path("resize_boundary"),
                SparseWriterConfig {
                    enable_preallocation: false,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            writer
                .write_chunk(&cx, 4, b"efgh", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.set_expected_size(4).is_err());
            assert_eq!(writer.lock_state().expected_size, None);
            writer.set_expected_size(8).unwrap();
            let path = writer.lock_state().temp_path.clone().unwrap();
            let bytes = std::fs::read(&path).unwrap();
            for size in [0, 4, 7] {
                assert!(matches!(
                    writer.set_expected_size(size),
                    Err(SparseWriterError::InvalidRange { offset: 4, size: 4 })
                ));
                assert_eq!(writer.lock_state().expected_size, Some(8));
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                assert_eq!(writer.get_stats().total_bytes_written, 4);
                assert!(!writer.is_complete());
            }
            writer
                .write_chunk(&cx, 0, b"abcd", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            writer.set_expected_size(12).unwrap();
            assert!(!writer.is_complete());
            writer
                .write_chunk(&cx, 8, b"ijkl", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            assert_eq!(std::fs::read(path).unwrap(), b"abcdefghijkl");
        });
    }

    #[test]
    fn test_overlapping_write_detection() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-overlap");
            let temp_dir = std::env::temp_dir();
            let final_path = temp_dir.join("test_overlap_output");

            let config = SparseWriterConfig::default();
            let writer = SparseWriter::new(&cx, object_id, final_path, config)
                .await
                .unwrap();

            let options = WriteOptions::default();

            // First write
            writer
                .write_chunk(&cx, 0, b"hello", options.clone())
                .await
                .unwrap();

            // Overlapping write should fail
            let result = writer.write_chunk(&cx, 2, b"world", options).await;
            assert!(matches!(
                result,
                Outcome::Err(SparseWriterError::OverlappingWrite { .. })
            ));
        });
    }

    #[test]
    fn test_preallocation() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-prealloc");
            let temp_dir = std::env::temp_dir();
            let final_path = temp_dir.join("test_prealloc_output");

            let mut config = SparseWriterConfig::default();
            config.enable_preallocation = true;

            let writer = SparseWriter::new(&cx, object_id, final_path, config)
                .await
                .unwrap();

            // Set expected size - should trigger preallocation
            writer.set_expected_size(1024 * 1024).unwrap();

            let stats = writer.get_stats();
            // Note: actual preallocation depends on platform support
            assert!(stats.allocated_size <= 1024 * 1024);
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn failed_preallocation_preserves_expected_size_and_completion() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let mut writer = SparseWriter::new(
                &cx,
                test_object_id("failed-preallocation"),
                unique_temp_path("failed_preallocation"),
                SparseWriterConfig {
                    enable_preallocation: true,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            Arc::make_mut(&mut writer.platform)
                .filesystem
                .supports_preallocation = true;
            writer.set_expected_size(4).unwrap();
            writer
                .write_chunk(&cx, 0, b"data", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            let before = writer.get_stats();
            assert!(matches!(
                writer.set_expected_size(u64::MAX),
                Err(SparseWriterError::PreallocationTooLarge { size: u64::MAX })
            ));
            let state = writer.lock_state();
            assert_eq!(state.expected_size, Some(4));
            assert_eq!(
                std::fs::read(state.temp_path.as_ref().unwrap()).unwrap(),
                b"data"
            );
            drop(state);
            assert!(writer.is_complete());
            let after = writer.get_stats();
            assert_eq!(before.allocated_size, after.allocated_size);
            assert_eq!(before.total_bytes_written, after.total_bytes_written);
        });
    }

    #[test]
    fn repeated_preallocation_preserves_payload_and_empty_file() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let mut writer = SparseWriter::new(
                &cx,
                test_object_id("preallocation-preservation"),
                unique_temp_path("preallocation_preservation"),
                SparseWriterConfig {
                    enable_preallocation: true,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            // Exercise the platform path even if capability probing on the
            // test filesystem conservatively reports no preallocation.
            Arc::make_mut(&mut writer.platform)
                .filesystem
                .supports_preallocation = true;
            writer.set_expected_size(0).unwrap();
            let path = {
                let mut state = writer.lock_state();
                writer.ensure_temp_file_open_locked(&mut state).unwrap();
                state.temp_path.clone().unwrap()
            };
            assert!(std::fs::read(&path).unwrap().is_empty());

            writer.set_expected_size(8).unwrap();
            writer
                .write_chunk(&cx, 0, b"abcdefgh", WriteOptions::default())
                .await
                .unwrap();
            for _ in 0..2 {
                writer.set_expected_size(8).unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), b"abcdefgh");
                assert!(writer.is_complete());
            }
            writer.set_expected_size(12).unwrap();
            assert_eq!(&std::fs::read(&path).unwrap()[..8], b"abcdefgh");
            writer
                .write_chunk(&cx, 8, b"ijkl", WriteOptions::default())
                .await
                .unwrap();
            writer.set_expected_size(12).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"abcdefghijkl");
            assert!(writer.is_complete());
        });
    }

    #[test]
    fn streaming_content_id_hash_matches_object_content_id_domain() {
        let content = b"content id domain regression guard";
        let path = unique_temp_path("content_id_domain");
        std::fs::write(&path, content).unwrap();
        let mut file = File::open(&path).unwrap();

        let streaming_hash =
            SparseWriter::hash_file_with_prefix(&mut file, Some(CONTENT_ID_DOMAIN)).unwrap();

        assert_eq!(streaming_hash, *ContentId::from_bytes(content).hash());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn stats_report_complete_ratio_for_zero_expected_size() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-zero-stats");
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("zero_stats"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();

            writer.set_expected_size(0).unwrap();

            let stats = writer.get_stats();
            assert_eq!(stats.completion_ratio, 1.0);
            assert!(writer.is_complete());
        });
    }

    #[test]
    fn verify_checks_manifest_content_hash_and_records_real_root() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"verified sparse writer content";
            let (object_id, manifest) = manifest_for_content(content);
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("verify_success"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();

            writer.set_expected_size(content.len() as u64).unwrap();
            writer
                .write_chunk(&cx, 0, content, WriteOptions::default())
                .await
                .unwrap();

            writer.verify(&cx, &manifest).await.unwrap();

            let stats = writer.get_stats();
            assert_eq!(
                stats.verification_state,
                VerificationState::Verified {
                    manifest_root: manifest.merkle_root
                }
            );
        });
    }

    #[test]
    fn commit_atomic_rename_closes_temp_handle_before_filesystem_move() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"verified sparse writer commit content";
            let (object_id, manifest) = manifest_for_content(content);
            let final_path = unique_temp_path("commit_atomic_final");
            let writer =
                SparseWriter::new(&cx, object_id, &final_path, SparseWriterConfig::default())
                    .await
                    .unwrap();

            writer.set_expected_size(content.len() as u64).unwrap();
            writer
                .write_chunk(&cx, 0, content, WriteOptions::default())
                .await
                .unwrap();
            writer.verify(&cx, &manifest).await.unwrap();

            let committed_path = writer.commit(&cx).await.unwrap();

            assert_eq!(committed_path, final_path);
            assert_eq!(std::fs::read(&committed_path).unwrap(), content);
            std::fs::remove_file(&committed_path).ok();
        });
    }

    #[test]
    fn durable_commit_policies_preserve_verified_bytes() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"durable destination bytes";
            for commit_policy in [
                CommitPolicy::AtomicRename,
                CommitPolicy::CopyAndVerify,
                CommitPolicy::LinkAndUnlink,
            ] {
                let (object_id, manifest) = manifest_for_content(content);
                let destination = unique_temp_path("durable_commit");
                let writer = SparseWriter::new(
                    &cx,
                    object_id,
                    &destination,
                    SparseWriterConfig {
                        commit_policy,
                        fsync_policy: super::super::FsyncPolicy::BeforeCommit,
                        ..SparseWriterConfig::default()
                    },
                )
                .await
                .unwrap();
                writer.set_expected_size(content.len() as u64).unwrap();
                writer
                    .write_chunk(&cx, 0, content, WriteOptions::default())
                    .await
                    .unwrap();
                writer.verify(&cx, &manifest).await.unwrap();
                assert_eq!(writer.commit(&cx).await.unwrap(), destination);
                assert_eq!(std::fs::read(destination).unwrap(), content);
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn directory_sync_errors_propagate_and_never_policy_skips_sync() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let mut writer = SparseWriter::new(
                &cx,
                test_object_id("sync_error"),
                unique_temp_path("sync_error"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();
            let missing_parent = unique_temp_path("missing_sync_parent").join("file");
            assert!(matches!(
                writer.sync_commit_destination(&missing_parent),
                Err(SparseWriterError::SyncFailed(_))
            ));
            writer.config.fsync_policy = super::super::FsyncPolicy::Never;
            writer.sync_commit_destination(&missing_parent).unwrap();
        });
    }

    #[test]
    fn verify_fails_closed_on_manifest_content_mismatch() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let expected = b"expected bytes";
            let actual = b"tampered bytes";
            assert_eq!(expected.len(), actual.len());
            let (object_id, manifest) = manifest_for_content(expected);
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("verify_mismatch"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();

            writer.set_expected_size(actual.len() as u64).unwrap();
            writer
                .write_chunk(&cx, 0, actual, WriteOptions::default())
                .await
                .unwrap();

            let result = writer.verify(&cx, &manifest).await;

            assert!(matches!(
                result,
                Outcome::Err(SparseWriterError::VerificationFailed(_))
            ));
            assert!(matches!(
                writer.get_stats().verification_state,
                VerificationState::Failed { .. }
            ));
        });
    }
