    use super::*;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    #[test]
    fn test_mailbox_transfer_id_generation() {
        let id1 = MailboxTransferId::new();
        let id2 = MailboxTransferId::new();

        assert_ne!(id1, id2);

        let bytes = id1.to_bytes();
        let reconstructed = MailboxTransferId::from_bytes(bytes);
        assert_eq!(id1, reconstructed);
    }

    #[test]
    fn test_peer_id_creation() {
        let peer = PeerId::new("test-peer-123");
        assert_eq!(peer.as_str(), "test-peer-123");
    }

    #[test]
    fn test_mailbox_config_defaults() {
        let config = MailboxConfig::default();

        assert_eq!(config.quota_limit, 100_000_000);
        assert_eq!(config.max_chunk_size, 1024 * 1024);
        assert!(config.tamper_detection);
        assert_eq!(config.operation_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_mailbox_event_serialization() -> TestResult {
        let event = MailboxEvent::TransferUploadStarted {
            transfer_id: MailboxTransferId::new(),
            destination: PeerId::new("peer-123"),
            total_size: 1024,
        };

        let serialized = serde_json::to_string(&event)?;
        let deserialized: MailboxEvent = serde_json::from_str(&serialized)?;

        assert!(matches!(
            (event, deserialized),
            (
                MailboxEvent::TransferUploadStarted { total_size: s1, .. },
                MailboxEvent::TransferUploadStarted { total_size: s2, .. },
            ) if s1 == s2
        ));
        Ok(())
    }

    #[test]
    fn test_mailbox_error_display() {
        let error = MailboxError::QuotaExceeded {
            usage: 1500,
            limit: 1000,
        };

        let display = format!("{}", error);
        assert!(display.contains("Quota exceeded"));
        assert!(display.contains("1500"));
        assert!(display.contains("1000"));
    }

    // Golden artifact tests for ATP mailbox protocol serialization stability
    // These tests freeze the JSON serialization format to detect unintended changes
    // Fixed timestamp: 1640995200000000 = 2022-01-01T00:00:00Z

    fn fixed_transfer_id() -> MailboxTransferId {
        MailboxTransferId::from_bytes([
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ])
    }

    #[test]
    fn parse_transfer_id_accepts_canonical_compact_and_uppercase() -> TestResult {
        let canonical = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let compact = canonical.replace('-', "");
        let uppercase = canonical.to_ascii_uppercase();

        assert_eq!(
            parse_transfer_id(canonical).map_err(std::io::Error::other)?,
            fixed_transfer_id()
        );
        assert_eq!(
            parse_transfer_id(&compact).map_err(std::io::Error::other)?,
            fixed_transfer_id()
        );
        assert_eq!(
            parse_transfer_id(&uppercase).map_err(std::io::Error::other)?,
            fixed_transfer_id()
        );
        Ok(())
    }

    #[test]
    fn parse_transfer_id_rejects_trailing_or_misplaced_hyphens() {
        let trailing_hyphen = "6ba7b8109dad11d180b400c04fd430c8-";
        let misplaced_hyphen = "6ba7b8109dad-11d1-80b4-00c04fd430-c8";

        assert!(parse_transfer_id(trailing_hyphen).is_err());
        assert!(parse_transfer_id(misplaced_hyphen).is_err());
    }

    #[test]
    fn parse_transfer_id_rejects_non_hex_bytes() {
        assert!(parse_transfer_id("6ba7b810-9dad-11d1-80b4-00c04fd430cg").is_err());
    }

    #[test]
    fn golden_mailbox_transfer_id_serialization() {
        let transfer_id = fixed_transfer_id();

        insta::assert_json_snapshot!(transfer_id, @r#""6ba7b810-9dad-11d1-80b4-00c04fd430c8""#);
    }

    #[test]
    fn golden_peer_id_serialization() {
        let peer_id = PeerId::new("peer-atp-node-f3c4d5e6");

        insta::assert_json_snapshot!(peer_id, @r#""peer-atp-node-f3c4d5e6""#);
    }

    #[test]
    fn golden_mailbox_transfer_metadata_serialization() {
        const CREATED_AT_NANOS: u64 = 1_640_995_200_000_000_000;
        const WEEK_NANOS: u64 = 604_800_000_000_000;

        let metadata = MailboxTransferMetadata {
            transfer_id: fixed_transfer_id(),
            destination_peer: PeerId::new("peer-destination-node"),
            created_at: Time::from_nanos(CREATED_AT_NANOS), // 2022-01-01T00:00:00Z
            expires_at: Time::from_nanos(CREATED_AT_NANOS + WEEK_NANOS), // +1 week
            total_size: 2048576,                            // 2MB
            chunk_count: 4,
            encrypted_metadata: vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
        };

        insta::assert_json_snapshot!(metadata, @r###"
        {
          "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
          "destination_peer": "peer-destination-node",
          "created_at": 1640995200000000000,
          "expires_at": 1641600000000000000,
          "total_size": 2048576,
          "chunk_count": 4,
          "encrypted_metadata": [
            222,
            173,
            190,
            239,
            202,
            254,
            186,
            190
          ]
        }
        "###);
    }

    #[test]
    fn golden_mailbox_operation_result_serialization() {
        use crate::atp::mailbox::quota::QuotaUsage;
        use std::time::UNIX_EPOCH;

        let result = MailboxOperationResult {
            success: true,
            transfer_id: Some(fixed_transfer_id()),
            quota_usage: QuotaUsage {
                bytes_used: 1048576, // 1MB
                active_transfers: 3,
                total_transfers: 15,
                last_updated: UNIX_EPOCH + std::time::Duration::from_secs(1640995200), // 2022-01-01T00:00:00Z
            },
            duration_ms: 1234,
            messages: vec![
                "Transfer initiated successfully".to_string(),
                "Encryption completed".to_string(),
            ],
            relay_receipt: Some("receipt-abc123def456".to_string()),
        };

        insta::assert_json_snapshot!(result, @r###"
        {
          "success": true,
          "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
          "quota_usage": {
            "bytes_used": 1048576,
            "active_transfers": 3,
            "total_transfers": 15,
            "last_updated": {
              "secs_since_epoch": 1640995200,
              "nanos_since_epoch": 0
            }
          },
          "duration_ms": 1234,
          "messages": [
            "Transfer initiated successfully",
            "Encryption completed"
          ],
          "relay_receipt": "receipt-abc123def456"
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_transfer_upload_started_serialization() {
        let event = MailboxEvent::TransferUploadStarted {
            transfer_id: fixed_transfer_id(),
            destination: PeerId::new("peer-upload-target"),
            total_size: 3145728, // 3MB
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "TransferUploadStarted": {
            "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "destination": "peer-upload-target",
            "total_size": 3145728
          }
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_quota_warning_serialization() {
        let event = MailboxEvent::QuotaWarning {
            current_usage: 85000000, // 85MB
            quota_limit: 100000000,  // 100MB
            utilization_percent: 85.0,
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "QuotaWarning": {
            "current_usage": 85000000,
            "quota_limit": 100000000,
            "utilization_percent": 85.0
          }
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_tamper_detected_serialization() {
        let event = MailboxEvent::TamperDetected {
            transfer_id: fixed_transfer_id(),
            tamper_type: "checksum_mismatch".to_string(),
            evidence: "expected_hash=abc123, actual_hash=def456".to_string(),
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "TamperDetected": {
            "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "tamper_type": "checksum_mismatch",
            "evidence": "expected_hash=abc123, actual_hash=def456"
          }
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_cleanup_performed_serialization() {
        let event = MailboxEvent::CleanupPerformed {
            expired_transfers: 7,
            bytes_freed: 15728640, // 15MB
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "CleanupPerformed": {
            "expired_transfers": 7,
            "bytes_freed": 15728640
          }
        }
        "###);
    }
