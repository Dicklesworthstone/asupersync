    use super::super::super::{Cli, Command};
    use super::*;
    use clap::Parser;

    #[test]
    fn new_journals_require_explicit_finite_snapshot_and_attempt_budgets() {
        for (attempts, snapshots, delay, valid) in [
            (4, 32, 250, true),
            (0, 32, 250, false),
            (1025, 32, 250, false),
            (4, 0, 250, false),
            (4, 65537, 250, false),
            (4, 32, 0, false),
        ] {
            assert_eq!(
                CreateOptions {
                    attempts,
                    max_snapshots: snapshots,
                    retry_delay_ms: delay
                }
                .validate()
                .is_ok(),
                valid
            );
        }
    }

    #[test]
    fn resume_requires_source_and_cannot_override_the_saved_budgets() {
        let args = [
            "atpd-live",
            "resume-journaled",
            "--config",
            "sender.json",
            "--input",
            "input.bin",
            "--journal",
            "sender.log",
        ];
        assert!(matches!(
            Cli::try_parse_from(args).unwrap().command,
            Command::ResumeJournaled { .. }
        ));
        for flag in ["--attempts", "--max-snapshots"] {
            let mut invalid = args.to_vec();
            invalid.extend([flag, "100"]);
            assert!(Cli::try_parse_from(invalid).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "atpd-live",
                "resume-journaled",
                "--config",
                "sender.json",
                "--journal",
                "sender.log"
            ])
            .is_err()
        );
    }

    #[test]
    fn journal_failure_is_not_delivery_or_transport_retry_permission() {
        let error = ResumeError::Journal(Box::new(
            asupersync::net::atp::sdk::native_auth::live::commit::resume::journal::SenderCheckpointPersistError {
                stored: false, interruption: None, source: Some(io::ErrorKind::StorageFull.into()),
            },
        ));
        assert!(!retryable(&error));
        let report = ResumeReport {
            outcome: Err(error),
            prefix: None,
            attempts: 1,
            receipt_reused: false,
            retained_epoch_bytes: 8,
            sink_written_bytes: 0,
            completed: None,
        };
        let result = report_json(&report);
        assert_eq!(result["status"], "journal_blocked");
        assert_eq!(result["persistence"]["storage_full"], true);
        assert!(result["receipt"].is_null());
    }
