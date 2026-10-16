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
