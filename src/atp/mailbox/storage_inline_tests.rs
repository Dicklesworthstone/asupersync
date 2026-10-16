    use super::*;
    use tempfile::TempDir;

    fn test_metadata(transfer_id: MailboxTransferId, total_size: u64) -> MailboxTransferMetadata {
        MailboxTransferMetadata {
            transfer_id,
            destination_peer: PeerId::new("test-peer"),
            created_at: mailbox_time_now(),
            expires_at: Time::from_nanos(
                mailbox_time_now()
                    .as_nanos()
                    .saturating_add(3_600_000_000_000),
            ),
            total_size,
            chunk_count: 1,
            encrypted_metadata: Vec::new(),
        }
    }

    #[test]
    fn test_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        assert_eq!(storage.entries.len(), 0);
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let transfer_id = MailboxTransferId::new();
        let metadata = test_metadata(transfer_id, 12);

        let test_data = b"Hello, World!".to_vec();

        // Store transfer
        storage
            .store_transfer(metadata, test_data.clone())
            .await
            .unwrap();
        assert_eq!(storage.entries.len(), 1);

        // Retrieve transfer
        let retrieved_data = storage
            .retrieve_transfer(&transfer_id, PeerId::new("requestor"))
            .await
            .unwrap();

        assert_eq!(retrieved_data, test_data);
    }

    #[tokio::test]
    async fn test_delete_transfer() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let transfer_id = MailboxTransferId::new();
        let metadata = test_metadata(transfer_id, 5);

        storage
            .store_transfer(metadata, b"test".to_vec())
            .await
            .unwrap();
        assert_eq!(storage.entries.len(), 1);

        storage.delete_transfer(&transfer_id).await.unwrap();
        assert_eq!(storage.entries.len(), 0);
    }

    #[test]
    fn test_storage_capacity_check() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            max_storage_size: 100,
            ..Default::default()
        };

        let storage = MailboxStorage::with_config(temp_dir.path().to_path_buf(), config).unwrap();

        assert!(storage.check_capacity(50).is_ok());
        assert!(storage.check_capacity(150).is_err());
    }

    #[test]
    fn storage_capacity_check_rejects_counter_overflow() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();
        storage.entries.insert(
            transfer_id,
            MailboxEntry {
                transfer_id,
                metadata: test_metadata(transfer_id, u64::MAX),
                chunks: Vec::new(),
                state: TransferState::Stored,
                storage_info: StorageInfo {
                    created_at: mailbox_time_now(),
                    last_accessed: mailbox_time_now(),
                    last_modified: mailbox_time_now(),
                    disk_size: u64::MAX,
                    original_size: 0,
                },
            },
        );

        assert!(matches!(
            storage.check_capacity(1),
            Err(MailboxError::QuotaExceeded {
                usage: u64::MAX,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn store_transfer_rejects_encoded_size_over_capacity_without_writing() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            max_storage_size: 1,
            ..Default::default()
        };
        let mut storage =
            MailboxStorage::with_config(temp_dir.path().to_path_buf(), config).unwrap();
        let transfer_id = MailboxTransferId::new();

        let result = storage
            .store_transfer(test_metadata(transfer_id, 1), b"x".to_vec())
            .await;

        assert!(matches!(result, Err(MailboxError::QuotaExceeded { .. })));
        assert!(storage.entries.is_empty());
        assert!(!temp_dir.path().join("transfers").exists());
    }

    #[tokio::test]
    async fn store_transfer_rejects_duplicate_transfer_id() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 1), b"a".to_vec())
            .await
            .unwrap();
        let result = storage
            .store_transfer(test_metadata(transfer_id, 1), b"b".to_vec())
            .await;

        assert!(matches!(
            result,
            Err(MailboxError::ConfigurationError { details }) if details.contains("already exists")
        ));
        assert_eq!(storage.entries.len(), 1);
    }

    #[tokio::test]
    async fn zero_chunk_size_is_treated_as_one_byte_chunks() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            chunk_size: 0,
            ..Default::default()
        };
        let mut storage =
            MailboxStorage::with_config(temp_dir.path().to_path_buf(), config).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 3), b"abc".to_vec())
            .await
            .unwrap();

        let entry = storage.entries.get(&transfer_id).expect("stored entry");
        assert_eq!(entry.chunks.len(), 3);
        let retrieved = storage
            .retrieve_transfer(&transfer_id, PeerId::new("requestor"))
            .await
            .unwrap();
        assert_eq!(retrieved, b"abc");
    }

    #[tokio::test]
    async fn retrieve_error_restores_stored_state() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 4), b"data".to_vec())
            .await
            .unwrap();
        let entry = storage.entries.get_mut(&transfer_id).expect("stored entry");
        entry.chunks[0].storage_path = format!("transfers/{transfer_id}/missing");

        let result = storage
            .retrieve_transfer(&transfer_id, PeerId::new("requestor"))
            .await;

        assert!(matches!(result, Err(MailboxError::NetworkError { .. })));
        assert!(matches!(
            storage
                .entries
                .get(&transfer_id)
                .expect("stored entry")
                .state,
            TransferState::Stored
        ));
    }

    #[tokio::test]
    async fn delete_transfer_rejects_escaping_chunk_path_without_removing_entry() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 4), b"data".to_vec())
            .await
            .unwrap();
        let entry = storage.entries.get_mut(&transfer_id).expect("stored entry");
        entry.chunks[0].storage_path = format!("transfers/{transfer_id}/../escape");

        let result = storage.delete_transfer(&transfer_id).await;

        assert!(matches!(result, Err(MailboxError::TamperDetected { .. })));
        assert!(storage.entries.contains_key(&transfer_id));
    }

    #[test]
    fn decode_chunk_rejects_unrepresentable_payload_length() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();
        let encoded = storage.encode_chunk(b"data").unwrap();
        let mut bytes = encoded.bytes;
        bytes[18..26].copy_from_slice(&u64::MAX.to_be_bytes());
        let chunk = StoredChunk {
            index: 0,
            size: bytes.len(),
            storage_path: format!("transfers/{transfer_id}/chunk_0000"),
            checksum: encoded.plaintext_sha256,
            compressed: encoded.compressed,
            encrypted: encoded.encrypted,
        };

        let result = storage.decode_chunk(transfer_id, &bytes, &chunk);

        assert!(matches!(result, Err(MailboxError::TamperDetected { .. })));
    }

    #[test]
    fn decode_chunk_rejects_invalid_metadata_checksum() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();
        let encoded = storage.encode_chunk(b"data").unwrap();
        let chunk = StoredChunk {
            index: 0,
            size: encoded.bytes.len(),
            storage_path: format!("transfers/{transfer_id}/chunk_0000"),
            checksum: "sha256:not-hex".to_string(),
            compressed: encoded.compressed,
            encrypted: encoded.encrypted,
        };

        let result = storage.decode_chunk(transfer_id, &encoded.bytes, &chunk);

        assert!(matches!(result, Err(MailboxError::TamperDetected { .. })));
    }

    #[test]
    fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let stats = storage.get_storage_stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }
