    use super::*;

    fn journal() -> Journal {
        Journal {
            version: JOURNAL_VERSION,
            file_name: "data.bin".into(),
            source_bytes: 7,
            source_sha256: [3; 32],
            remote: "127.0.0.1:1234".parse().unwrap(),
            server_name: "localhost".into(),
            local_peer_label: "01".repeat(32),
            state: NativeCheckpointState::Prepared,
            attempt: 0,
            receipt: None,
            cancelled: false,
        }
    }

    #[test]
    fn checkpoint_schema_rejects_invalid_lifecycle_versions_and_paths() {
        let original = journal();
        original.validate().unwrap();
        for name in ["..", "../outside", "a/b", "a\\b", "NUL"] {
            let mut invalid = original.clone();
            invalid.file_name = name.into();
            assert!(invalid.validate().is_err());
        }
        let mut invalid = original.clone();
        invalid.version += 1;
        assert!(invalid.validate().is_err());
        let mut invalid = original.clone();
        invalid.attempt = 1;
        assert!(invalid.validate().is_err());
        for state in [
            NativeCheckpointState::Sending,
            NativeCheckpointState::Acknowledged,
        ] {
            let mut invalid = original.clone();
            invalid.state = state;
            assert!(invalid.validate().is_err());
        }
        let mut sending = original;
        sending.state = NativeCheckpointState::Sending;
        sending.attempt = 1;
        sending.validate().unwrap();
        sending.attempt = MAX_CHECKPOINT_ATTEMPTS + 1;
        assert!(sending.validate().is_err());
    }

    #[test]
    fn checkpoint_json_is_versioned_and_rejects_unknown_or_duplicate_fields() {
        let bytes = serde_json::to_vec(&journal()).unwrap();
        let decoded: Journal = serde_json::from_slice(&bytes).unwrap();
        decoded.validate().unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(serde_json::from_str::<Journal>(&json.replacen('{', "{\"extra\":1,", 1)).is_err());
        assert!(
            serde_json::from_str::<Journal>(&json.replacen('{', "{\"version\":1,", 1)).is_err()
        );
    }

    #[test]
    fn retries_require_exact_uncertain_attempt_and_never_reset_the_budget() {
        let mut record = journal();
        assert_eq!(
            record.next_attempt(NativeCheckpointRetry::Never).unwrap(),
            1
        );
        assert!(matches!(
            record.next_attempt(NativeCheckpointRetry::AcknowledgeUncertain { attempt: 0 }),
            Err(NativeCheckpointError::StaleAttempt)
        ));
        record.state = NativeCheckpointState::Sending;
        for attempt in 1..=MAX_CHECKPOINT_ATTEMPTS {
            record.attempt = attempt;
            assert!(matches!(record.next_attempt(NativeCheckpointRetry::Never),
                Err(NativeCheckpointError::Uncertain { attempt: actual }) if actual == attempt));
            assert!(matches!(
                record.next_attempt(NativeCheckpointRetry::AcknowledgeUncertain {
                    attempt: attempt - 1
                }),
                Err(NativeCheckpointError::StaleAttempt)
            ));
            let next = record.next_attempt(NativeCheckpointRetry::AcknowledgeUncertain { attempt });
            if attempt == MAX_CHECKPOINT_ATTEMPTS {
                assert!(matches!(
                    next,
                    Err(NativeCheckpointError::AttemptsExhausted)
                ));
            } else {
                assert_eq!(next.unwrap(), attempt + 1);
            }
        }
    }

    #[test]
    fn acknowledged_journal_retains_the_actual_receipt_and_rejects_inconsistent_facts() {
        let mut record = journal();
        let report = SendReport {
            transfer_id: "actual-transfer".into(),
            bytes_sent: 7,
            files: 1,
            symbols_sent: 13,
            feedback_rounds: 2,
            merkle_root_hex: "ab".repeat(32),
            peer: record.remote,
            receipt: ReceiveReceipt {
                committed: true,
                bytes_received: 7,
                files: 1,
                sha_ok: true,
                merkle_ok: true,
                symbols_accepted: 12,
                feedback_rounds: 2,
                decode_count: 1,
                decode_micros: 99,
                reason: None,
                committed_paths: vec!["/data/data.bin".into()],
            },
        };
        record.state = NativeCheckpointState::Acknowledged;
        record.attempt = 2;
        record.receipt = Some(StoredReceipt::capture(&report));
        record.validate().unwrap();
        let mut revoked_success = record.clone();
        revoked_success.version = CANCELLED_JOURNAL_VERSION;
        revoked_success.cancelled = true;
        assert!(matches!(
            revoked_success.validate(),
            Err(NativeCheckpointError::Invalid("acknowledged delivery cannot be cancelled"))
        ));
        let restored: Journal =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        restored.validate().unwrap();
        let retained = restored.receipt.unwrap().report();
        assert_eq!(retained.receipt, report.receipt);
        assert_eq!(retained.transfer_id, report.transfer_id);
        assert_eq!(retained.merkle_root_hex, report.merkle_root_hex);
        for kind in 0..5 {
            let mut wrong = record.clone();
            let receipt = wrong.receipt.as_mut().unwrap();
            match kind {
                0 => receipt.peer.set_port(1235),
                1 => receipt.receipt.bytes_received += 1,
                2 => receipt.receipt.sha_ok = false,
                3 => receipt.receipt.merkle_ok = false,
                _ => receipt.receipt.committed = false,
            }
            assert!(wrong.validate().is_err(), "kind={kind}");
        }
    }

    // The pre-cancellation decoder's exact field inventory and version check.
    // It must retain compatibility for live v1 journals and refuse a terminal
    // v2 rather than silently treating retained payload bytes as sendable.
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct VersionOneJournal {
        version: u32,
        file_name: String,
        source_bytes: u64,
        source_sha256: [u8; 32],
        remote: SocketAddr,
        server_name: String,
        local_peer_label: String,
        state: NativeCheckpointState,
        attempt: u64,
        receipt: Option<StoredReceipt>,
    }

    fn read_version_one(bytes: &[u8]) -> Result<VersionOneJournal, &'static str> {
        let record: VersionOneJournal =
            serde_json::from_slice(bytes).map_err(|_| "old decoder refused")?;
        if record.version != JOURNAL_VERSION {
            return Err("old version check refused");
        }
        Ok(record)
    }

    #[test]
    fn cancellation_tombstones_preserve_live_v1_bytes_and_old_readers_fail_closed() {
        for sending in [false, true] {
            let mut record = journal();
            if sending {
                record.state = NativeCheckpointState::Sending;
                record.attempt = 3;
            }
            let original = serde_json::to_vec(&record).unwrap();
            let old = read_version_one(&original).unwrap();
            assert_eq!(serde_json::to_vec(&old).unwrap(), original);
            assert!(!String::from_utf8(original).unwrap().contains("cancelled"));

            record.cancelled = true;
            record.version = CANCELLED_JOURNAL_VERSION;
            record.validate().unwrap();
            let bytes = serde_json::to_vec(&record).unwrap();
            assert!(read_version_one(&bytes).is_err());
            let mut version_only: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            version_only.as_object_mut().unwrap().remove("cancelled");
            assert_eq!(
                read_version_one(&serde_json::to_vec(&version_only).unwrap())
                    .err()
                    .unwrap(),
                "old version check refused"
            );

            let restored: Journal = serde_json::from_slice(&bytes).unwrap();
            restored.validate().unwrap();
            for retry in [
                NativeCheckpointRetry::Never,
                NativeCheckpointRetry::AcknowledgeUncertain {
                    attempt: restored.attempt,
                },
            ] {
                assert!(matches!(
                    restored.next_attempt(retry),
                    Err(NativeCheckpointError::Cancelled { attempt, delivery_uncertain })
                        if attempt == restored.attempt && delivery_uncertain == sending
                ));
            }
            let status = restored.status(PathBuf::from("/retained/checkpoint"));
            assert!(status.cancelled);
            assert_eq!(status.delivery_uncertain(), sending);
            assert!(status.receipt.is_none());
        }
    }

    #[test]
    fn cancellation_tombstones_reject_incoherent_versions_lifecycles_and_duplicate_flags() {
        let mut record = journal();
        record.version = CANCELLED_JOURNAL_VERSION;
        record.cancelled = true;
        record.validate().unwrap();
        for mutation in 0..6 {
            let mut changed = record.clone();
            match mutation {
                0 => changed.version = JOURNAL_VERSION,
                1 => changed.version += 1,
                2 => changed.cancelled = false,
                3 => changed.state = NativeCheckpointState::Acknowledged,
                4 => changed.attempt = 1,
                5 => changed.state = NativeCheckpointState::Sending,
                _ => unreachable!(),
            }
            assert!(changed.validate().is_err(), "mutation={mutation}");
        }
        let bytes = serde_json::to_string(&record).unwrap();
        for malformed in [
            bytes.replacen('{', "{\"cancelled\":true,", 1),
            bytes.replacen("\"cancelled\":true", "\"cancelled\":null", 1),
            bytes.replacen("\"cancelled\":true", "\"cancelled\":\"true\"", 1),
        ] {
            assert!(serde_json::from_str::<Journal>(&malformed).is_err());
        }
    }

    #[test]
    fn cancellation_snapshot_binds_source_destination_and_exact_attempt() {
        let directory = PathBuf::from("/retained/checkpoint");
        let original = journal();
        let expected = original.info(directory.clone());
        original
            .check_cancellation_snapshot(&directory, &expected)
            .unwrap();
        for mutation in 0..7 {
            let mut wrong = expected.clone();
            match mutation {
                0 => wrong.directory.push("other"),
                1 => wrong.remote.set_port(1235),
                2 => wrong.file_name.push('x'),
                3 => wrong.source_bytes += 1,
                4 => wrong.source_sha256[0] ^= 1,
                5 => wrong.attempt += 1,
                6 => wrong.state = NativeCheckpointState::Sending,
                _ => unreachable!(),
            }
            let result = original.check_cancellation_snapshot(&directory, &wrong);
            if mutation < 5 {
                assert!(matches!(result, Err(NativeCheckpointError::SnapshotMismatch)));
            } else {
                assert!(matches!(result, Err(NativeCheckpointError::StaleAttempt)));
            }
        }
        let mut sending = original;
        sending.state = NativeCheckpointState::Sending;
        sending.attempt = 1;
        assert!(matches!(
            sending.check_cancellation_snapshot(&directory, &expected),
            Err(NativeCheckpointError::StaleAttempt)
        ));
        let expected = sending.info(directory.clone());
        sending.cancelled = true;
        sending.version = CANCELLED_JOURNAL_VERSION;
        sending.validate().unwrap();
        sending
            .check_cancellation_snapshot(&directory, &expected)
            .unwrap();
    }
