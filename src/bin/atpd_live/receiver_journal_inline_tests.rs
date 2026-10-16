    use super::super::{Cli, Command};
    use super::*;
    use clap::Parser;

    #[test]
    fn receiver_restore_cannot_reset_attempts_or_storage_budgets() {
        let args = [
            "atpd-live",
            "resume-receiver",
            "--config",
            "receiver.json",
            "--journal",
            "/private/receiver.wal",
            "--data",
            "/inbox/receiver.data",
        ];
        assert!(matches!(
            Cli::try_parse_from(args).unwrap().command,
            Command::ResumeReceiver { .. }
        ));
        for flag in ["--attempts", "--max-snapshots", "--max-journal-bytes"] {
            let mut invalid = args.to_vec();
            invalid.extend([flag, "4"]);
            assert!(Cli::try_parse_from(invalid).is_err());
        }
        let args = [
            "atpd-live",
            "receive-journaled",
            "--config",
            "receiver.json",
            "--journal",
            "/private/receiver.wal",
            "--data",
            "/inbox/receiver.data",
            "--attempts",
            "4",
            "--max-snapshots",
            "32",
            "--max-journal-bytes",
            "65536",
        ];
        let Command::ReceiveJournaled { options, .. } = Cli::try_parse_from(args).unwrap().command
        else {
            panic!("wrong command");
        };
        assert_eq!(options.limits(1024).unwrap().max_data_bytes, 1024);
        assert!(
            CreateOptions {
                attempts: 0,
                ..options
            }
            .limits(1024)
            .is_err()
        );
        assert!(
            CreateOptions {
                max_snapshots: 65_537,
                ..options
            }
            .limits(1024)
            .is_err()
        );
        assert!(
            CreateOptions {
                max_journal_bytes: 134_217_729,
                ..options
            }
            .limits(1024)
            .is_err()
        );
    }

    #[test]
    fn compact_receiver_cli_selects_its_own_limits_without_changing_legacy_defaults() {
        let Command::ReceiveJournaled {
            intent, options, ..
        } = Cli::try_parse_from([
            "atpd-live",
            "receive-journaled",
            "--config",
            "receiver.json",
            "--journal",
            "/private/receiver.wal",
            "--data",
            "/inbox/receiver.data",
            "--intent",
            "/private/receiver.intent",
            "--attempts",
            "16",
            "--max-snapshots",
            "262144",
            "--max-journal-bytes",
            "67108864",
        ])
        .unwrap()
        .command
        else {
            panic!("wrong command");
        };
        assert_eq!(intent, Some(PathBuf::from("/private/receiver.intent")));
        let limits = options.compact_limits(4 * 1024 * 1024 * 1024).unwrap();
        assert_eq!(limits.max_snapshots, 262_144);
        assert_eq!(limits.max_journal_bytes, 67_108_864);
        assert_eq!(limits.max_data_bytes, 4 * 1024 * 1024 * 1024);
        assert!(options.limits(1024).is_err());
        for invalid in [
            CreateOptions {
                max_snapshots: 1_048_577,
                ..options
            },
            CreateOptions {
                max_journal_bytes: 127,
                ..options
            },
            CreateOptions {
                max_journal_bytes: 134_217_729,
                ..options
            },
        ] {
            assert!(invalid.compact_limits(1024).is_err());
        }
        let Command::ResumeReceiver { intent, .. } = Cli::try_parse_from([
            "atpd-live",
            "resume-receiver",
            "--config",
            "receiver.json",
            "--journal",
            "/private/receiver.wal",
            "--data",
            "/inbox/receiver.data",
            "--intent",
            "/private/receiver.intent",
        ])
        .unwrap()
        .command
        else {
            panic!("wrong command");
        };
        assert_eq!(intent, Some(PathBuf::from("/private/receiver.intent")));
    }

    #[test]
    fn proof_reconnects_cannot_extend_the_first_retention_deadline() {
        let first = first_deadline(None, 7, 2);
        assert_eq!(first, 2_000_000_007);
        assert_eq!(first_deadline(Some(first), first - 1, 100), first);
        assert_eq!(first_deadline(Some(first), first + 1, 100), first);
        assert_eq!(first_deadline(None, u64::MAX - 1, 1), u64::MAX);
    }

    #[test]
    fn persisted_checkpoint_interruption_is_not_delivery_or_retry_permission() {
        use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::ReceiverCheckpointPersistError;
        let error = ResumeError::ReceiverJournal(Box::new(ReceiverCheckpointPersistError {
            stored: true,
            interruption: Some(Box::new(LiveStreamError::Timeout("receiver checkpoint"))),
            source: None,
        }));
        assert!(!retryable(&error));
        let report = ResumeReport {
            outcome: Err(error),
            prefix: None,
            attempts: 1,
            receipt_reused: false,
            retained_epoch_bytes: 8,
            sink_written_bytes: 3,
            completed: None,
        };
        let record = transfer_json(&report);
        assert_eq!(record["status"], "journal_blocked");
        assert_eq!(record["persistence"]["stored"], true);
        assert_eq!(record["persistence"]["interrupted"], true);
        assert!(record["receipt"].is_null());
        assert!(record["completed_receipt"].is_null());
        assert!(!retryable(&ResumeError::LocalFailure));
    }
