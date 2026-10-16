    use super::*;
    use crate::atp::object::ContentId;
    use crate::cx::Cx;

    #[test]
    fn test_writer_config_defaults() {
        let config = WriterConfig::default();
        assert_eq!(config.chunk_size, 256 * 1024);
        assert_eq!(config.max_concurrent_chunks, 8);
        assert!(config.enable_progress);
        assert!(config.enable_resume);
        assert_eq!(config.proof_mode, ProofMode::Full);
    }

    #[test]
    fn test_resume_token_validity() {
        let token = ResumeToken {
            transfer_id: TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]),
            object_id: ObjectId::content(ContentId::new([1; 32])),
            verified_bytes: 1024,
            manifest_root: MerkleRoot::zero(),
            journal_position: 1024,
            created_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
        };

        assert!(token.is_valid());
        assert_eq!(token.verified_offset(), 1024);
    }

    #[test]
    fn test_writer_progress() {
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let writer = AtpWriter::new(object_id, [2; 32], WriterConfig::default());

        let progress = writer.progress();
        assert_eq!(progress.bytes_written, 0);
        assert_eq!(progress.state, WriterState::Ready);
        assert_eq!(progress.chunks_completed, 0);
    }

    #[test]
    fn test_writer_progress_handles_zero_chunk_size() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let mut config = WriterConfig::default();
            config.chunk_size = 0;
            config.min_chunk_size = 0;
            config.max_chunk_size = 0;
            config.backpressure_threshold = 0;

            let mut writer = AtpWriter::new(object_id, [2; 32], config);
            assert_eq!(writer.progress().chunks_completed, 0);

            let bytes_written = writer.write_all(&cx, b"abc").await.unwrap();
            assert_eq!(bytes_written, 3);
            assert_eq!(writer.progress().chunks_completed, 3);
        });
    }

    #[test]
    fn pending_buffer_length_overflow_fails_closed() {
        let result = checked_pending_buffer_len(usize::MAX, 1);

        assert!(matches!(
            result,
            Err(AtpError::Protocol(ProtocolError::FrameTooLarge))
        ));
    }

    #[test]
    fn test_resumed_write_overflow_fails_closed_before_mutating_proof_state() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let transfer_id = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);
            let token = ResumeToken {
                transfer_id,
                object_id,
                verified_bytes: u64::MAX,
                manifest_root: MerkleRoot::new([9; 32]),
                journal_position: u64::MAX,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            };

            let mut writer =
                AtpWriter::from_resume_token(token, [2; 32], WriterConfig::default()).unwrap();
            let result = writer.write_all(&cx, b"x").await;

            assert!(matches!(
                result,
                Outcome::Err(AtpError::Protocol(ProtocolError::FrameTooLarge))
            ));
            assert_eq!(writer.bytes_written, u64::MAX);
            assert_eq!(writer.buffer.as_slice(), b"x");
            assert!(writer.verified_chunks.is_empty());
        });
    }

    #[tokio::test]
    async fn test_writer_lifecycle() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let config = WriterConfig::default();

        let mut writer = AtpWriter::new(object_id, remote_peer, config);
        assert_eq!(writer.state(), WriterState::Ready);

        // Write some data
        let data = b"Hello, ATP World!";
        let bytes_written = writer.write_all(&cx, data).await.unwrap();
        assert_eq!(bytes_written, data.len());
        assert_eq!(writer.state(), WriterState::Streaming);

        // Check progress
        let progress = writer.progress();
        assert!(progress.bytes_written >= data.len() as u64);

        // Finalize refuses rather than fabricate a TransferProof (asupersync-txa7vi)
        let result = writer.finalize(&cx).await;
        assert!(matches!(
            result,
            Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
        ));
        assert_eq!(writer.state(), WriterState::Error);
    }

    #[test]
    fn completed_writer_rejects_late_writes_without_state_mutation() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let mut writer = AtpWriter::new(object_id, [2; 32], WriterConfig::default());

            let result = writer.write_buffer(&cx, b"final payload").await;
            assert!(matches!(
                result,
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
            ));
            let completed_bytes = writer.bytes_written;
            let completed_chunks = writer.verified_chunks.len();

            let late_write = writer.write_all(&cx, b"late bytes").await;

            assert!(matches!(
                late_write,
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
            ));
            assert_eq!(writer.state(), WriterState::Error);
            assert_eq!(writer.bytes_written, completed_bytes);
            assert_eq!(writer.verified_chunks.len(), completed_chunks);
            assert_eq!(writer.buffer, Vec::<u8>::new());
        });
    }

    #[test]
    fn completed_writer_rejects_cancellation_resume_token() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let mut writer = AtpWriter::new(object_id, [2; 32], WriterConfig::default());

            let result = writer
                .write_buffer(&cx, b"cannot resume this")
                .await;
            assert!(matches!(
                result,
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
            ));
            let cancellation = writer.cancel(&cx).await;

            assert!(matches!(
                cancellation,
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
            ));
            assert_eq!(writer.state(), WriterState::Error);
            assert!(writer.resume_token.is_none());
        });
    }

    #[test]
    fn test_writer_refuses_to_fabricate_proof() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let remote_peer = [9; 32];
            let config = WriterConfig::default();
            let mut writer_a = AtpWriter::new(
                ObjectId::content(ContentId::new([0; 32])),
                remote_peer,
                config.clone(),
            );
            let mut writer_b = AtpWriter::new(
                ObjectId::content(ContentId::new([0; 32])),
                remote_peer,
                config,
            );

            let result_a = writer_a.write_buffer(&cx, b"payload-A").await;
            let result_b = writer_b.write_buffer(&cx, b"payload-B").await;

            assert!(matches!(
                result_a,
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
            ));
            assert!(matches!(
                result_b,
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
            ));
        });
    }

    #[tokio::test]
    async fn test_write_file_streams_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let payload = b"chunk-one/chunk-two/chunk-three";
        std::fs::write(&path, payload).unwrap();

        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.chunk_size = 5;
        config.min_chunk_size = 1;
        config.max_chunk_size = 5;
        config.backpressure_threshold = 8;

        let mut writer = AtpWriter::new(object_id, remote_peer, config);
        let result = writer.write_file(&cx, &path).await;
        assert!(matches!(
            result,
            Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
        ));

        assert_eq!(writer.state(), WriterState::Error);
        assert_eq!(writer.bytes_written, payload.len() as u64);
    }

    #[tokio::test]
    async fn test_writer_cancellation() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.enable_resume = true;

        let mut writer = AtpWriter::new(object_id, remote_peer, config);

        // Write some data
        let data = b"Partial data";
        writer.write_all(&cx, data).await.unwrap();

        // Cancel and get resume token
        let resume_token = writer.cancel(&cx).await.unwrap();
        assert_eq!(writer.state(), WriterState::Cancelled);
        assert!(resume_token.is_valid());
        assert_eq!(resume_token.verified_bytes, data.len() as u64);
    }

    #[tokio::test]
    async fn test_sink_operations() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let config = WriterConfig::default();

        let mut sink = AtpSink::new(object_id, remote_peer, config);

        // Send data
        let data = b"Sink data stream";
        sink.send(&cx, data).await.unwrap();

        // Check progress
        let progress = sink.progress();
        assert!(progress.bytes_written >= data.len() as u64);

        // Close refuses to mint a TransferProof without transport
        let result = sink.close(&cx).await;
        assert!(matches!(
            result,
            Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
        ));
    }

    #[tokio::test]
    async fn test_resume_from_token() {
        let cx = Cx::for_testing();
        // Create initial writer
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.enable_resume = true;

        let mut writer1 = AtpWriter::new(object_id.clone(), remote_peer, config.clone());
        writer1.write_all(&cx, b"First part").await.unwrap();
        let resume_token = writer1.cancel(&cx).await.unwrap();

        // Resume with new writer
        let mut writer2 = AtpWriter::from_resume_token(resume_token, remote_peer, config).unwrap();
        writer2.write_all(&cx, b" Second part").await.unwrap();
        let result = writer2.finalize(&cx).await;
        assert!(matches!(
            result,
            Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
        ));

        assert_eq!(writer2.state(), WriterState::Error);
        assert!(writer2.bytes_written >= 21); // "First part Second part"
    }

    #[tokio::test]
    async fn test_backpressure_handling() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.backpressure_threshold = 1024; // Small threshold for testing

        let mut writer = AtpWriter::new(object_id, remote_peer, config);

        // Write data larger than backpressure threshold
        let large_data = vec![42u8; 2048];
        writer.write_all(&cx, &large_data).await.unwrap();

        // Writer should handle backpressure internally
        assert_ne!(writer.state(), WriterState::Error);

        let result = writer.finalize(&cx).await;
        assert!(matches!(
            result,
            Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
        ));
        assert_eq!(writer.bytes_written, large_data.len() as u64);
    }
