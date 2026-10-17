    use super::*;

    async fn test_client() -> MailboxClient {
        MailboxClient::new(MailboxConfig::default())
            .await
            .expect("mailbox client should initialize")
    }

    fn test_transfer_metadata(
        transfer_id: MailboxTransferId,
        destination_peer: PeerId,
        chunk_count: u32,
        encrypted_metadata: Vec<u8>,
    ) -> MailboxTransferMetadata {
        let created_at = mailbox_time_now();
        MailboxTransferMetadata {
            transfer_id,
            destination_peer,
            created_at,
            expires_at: created_at + std::time::Duration::from_secs(60),
            total_size: 0,
            chunk_count,
            encrypted_metadata,
        }
    }

    #[tokio::test]
    async fn test_mailbox_client_creation() {
        let config = MailboxConfig::default();
        let result = MailboxClient::new(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn decrypt_and_verify_accepts_bound_metadata() {
        let client = test_client().await;
        let transfer_id = MailboxTransferId::new();
        let destination_peer = PeerId::new("recipient-peer");
        let data = b"bound mailbox payload";
        let chunks = client
            .encrypt_payload_chunks(data)
            .expect("payload encryption should succeed");
        let chunk_count = u32::try_from(chunks.len()).expect("test chunk count should fit in u32");
        let encrypted_metadata = client
            .encrypt_transfer_metadata(transfer_id, &destination_peer, data, chunk_count)
            .expect("metadata encryption should succeed");
        let metadata = test_transfer_metadata(
            transfer_id,
            destination_peer,
            chunk_count,
            encrypted_metadata,
        );

        let plaintext = client
            .decrypt_and_verify_transfer(transfer_id, chunks, metadata)
            .expect("bound metadata should verify");

        assert_eq!(plaintext, data);
    }

    #[tokio::test]
    async fn decrypt_and_verify_rejects_replayed_transfer_id() {
        let client = test_client().await;
        let original_transfer_id = MailboxTransferId::new();
        let requested_transfer_id = MailboxTransferId::new();
        let destination_peer = PeerId::new("recipient-peer");
        let data = b"replayed mailbox payload";
        let chunks = client
            .encrypt_payload_chunks(data)
            .expect("payload encryption should succeed");
        let chunk_count = u32::try_from(chunks.len()).expect("test chunk count should fit in u32");
        let encrypted_metadata = client
            .encrypt_transfer_metadata(original_transfer_id, &destination_peer, data, chunk_count)
            .expect("metadata encryption should succeed");
        let metadata = test_transfer_metadata(
            requested_transfer_id,
            destination_peer,
            chunk_count,
            encrypted_metadata,
        );

        let result = client.decrypt_and_verify_transfer(requested_transfer_id, chunks, metadata);

        assert!(matches!(
            result,
            Err(MailboxError::TamperDetected { evidence, .. })
                if evidence.contains("transfer id")
        ));
    }

    #[tokio::test]
    async fn decrypt_and_verify_rejects_replayed_destination_peer() {
        let client = test_client().await;
        let transfer_id = MailboxTransferId::new();
        let encrypted_destination_peer = PeerId::new("original-recipient");
        let public_destination_peer = PeerId::new("rewritten-recipient");
        let data = b"destination-bound payload";
        let chunks = client
            .encrypt_payload_chunks(data)
            .expect("payload encryption should succeed");
        let chunk_count = u32::try_from(chunks.len()).expect("test chunk count should fit in u32");
        let encrypted_metadata = client
            .encrypt_transfer_metadata(transfer_id, &encrypted_destination_peer, data, chunk_count)
            .expect("metadata encryption should succeed");
        let metadata = test_transfer_metadata(
            transfer_id,
            public_destination_peer,
            chunk_count,
            encrypted_metadata,
        );

        let result = client.decrypt_and_verify_transfer(transfer_id, chunks, metadata);

        assert!(matches!(
            result,
            Err(MailboxError::TamperDetected { evidence, .. })
                if evidence.contains("destination peer")
        ));
    }

    #[tokio::test]
    async fn decrypt_and_verify_rejects_malformed_plaintext_hash() {
        let client = test_client().await;
        let transfer_id = MailboxTransferId::new();
        let destination_peer = PeerId::new("recipient-peer");
        let data = b"hash-bound payload";
        let chunks = client
            .encrypt_payload_chunks(data)
            .expect("payload encryption should succeed");
        let chunk_count = u32::try_from(chunks.len()).expect("test chunk count should fit in u32");
        let metadata_plaintext = ClientEncryptedMetadata {
            transfer_id,
            destination_peer: destination_peer.clone(),
            plaintext_size: u64::try_from(data.len()).expect("test payload size should fit in u64"),
            plaintext_sha256: "not-hex".to_string(),
            plaintext_chunk_sizes: vec![
                u64::try_from(data.len()).expect("test payload size should fit in u64"),
            ],
            encrypted_chunk_count: chunk_count,
        };
        let metadata_bytes = serde_json::to_vec(&metadata_plaintext)
            .expect("test encrypted metadata should serialize");
        let metadata_envelope = EncryptedChunk::encrypt(&metadata_bytes, &client.encryption_key)
            .expect("metadata encryption should succeed");
        let encrypted_metadata = serde_json::to_vec(&metadata_envelope)
            .expect("test metadata envelope should serialize");
        let metadata = test_transfer_metadata(
            transfer_id,
            destination_peer,
            chunk_count,
            encrypted_metadata,
        );

        let result = client.decrypt_and_verify_transfer(transfer_id, chunks, metadata);

        assert!(matches!(
            result,
            Err(MailboxError::TamperDetected { evidence, .. })
                if evidence.contains("sha256 is malformed")
        ));
    }
