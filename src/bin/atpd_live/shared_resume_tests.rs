//! Pure policy boundaries and truthful terminal-result projections.

use super::*;
use asupersync::net::atp::sdk::NativeClientCertificateId;
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamPrefix, LiveStreamReceipt};
use clap::Parser;

fn options() -> Options {
    Options {
        max_sessions: 4,
        max_sessions_per_client: 2,
        max_session_keys: 8,
        attempts_per_session: 3,
        idle_retention_secs: 10,
        proof_recovery_secs: 5,
    }
}

fn key() -> ResumeSessionKey {
    ResumeSessionKey {
        client: NativeClientCertificateId::from_sha256([7; 32]),
        nonce: [9; 32],
    }
}

fn receipt() -> LiveStreamReceipt {
    LiveStreamReceipt {
        prefix: LiveStreamPrefix {
            stream_nonce: [9; 32],
            epochs: 1,
            bytes: 4,
            chain: [3; 32],
        },
        source_sha256: [5; 32],
    }
}

#[test]
fn connection_resident_client_and_lifetime_limits_are_independent() {
    let limits = options().config(2).unwrap();
    assert_eq!(
        (
            limits.max_connections,
            limits.max_sessions,
            limits.max_sessions_per_client
        ),
        (2, 4, 2)
    );
    assert_eq!(
        (limits.max_session_keys, limits.max_attempts_per_session),
        (8, 3)
    );
    for invalid in [
        Options {
            max_sessions: 0,
            ..options()
        },
        Options {
            max_sessions: 1025,
            ..options()
        },
        Options {
            max_sessions_per_client: 0,
            ..options()
        },
        Options {
            max_sessions_per_client: 5,
            ..options()
        },
        Options {
            max_session_keys: 3,
            ..options()
        },
        Options {
            max_session_keys: 65_537,
            ..options()
        },
        Options {
            attempts_per_session: 0,
            ..options()
        },
        Options {
            attempts_per_session: 1025,
            ..options()
        },
        Options {
            idle_retention_secs: 0,
            ..options()
        },
        Options {
            idle_retention_secs: 86_401,
            ..options()
        },
        Options {
            proof_recovery_secs: 0,
            ..options()
        },
        Options {
            proof_recovery_secs: u64::MAX,
            ..options()
        },
    ] {
        assert!(invalid.config(2).is_err(), "accepted {invalid:?}");
    }
    for connections in [0, 5, u32::MAX] {
        assert!(options().config(connections).is_err());
    }
}

#[test]
fn shared_command_requires_explicit_budgets_and_keeps_existing_commands() {
    use super::super::{Cli, Command};
    let args = [
        "atpd-live",
        "serve-resumable",
        "--config",
        "receiver.json",
        "--max-sessions",
        "4",
        "--max-sessions-per-client",
        "2",
        "--max-session-keys",
        "8",
        "--attempts-per-session",
        "3",
    ];
    let cli = Cli::try_parse_from(args).unwrap();
    match cli.command {
        Command::ServeResumable { options, .. } => {
            assert_eq!(options.config(2).unwrap().max_sessions, 4);
            assert_eq!(
                (options.idle_retention_secs, options.proof_recovery_secs),
                (300, 30)
            );
        }
        _ => panic!("new command was not selected"),
    }
    assert!(Cli::try_parse_from(&args[..args.len() - 2]).is_err());
    assert!(matches!(
        Cli::try_parse_from(["atpd-live", "serve", "--config", "receiver.json"])
            .unwrap()
            .command,
        Command::Serve { .. }
    ));
    assert!(matches!(
        Cli::try_parse_from([
            "atpd-live",
            "send-resumable",
            "--config",
            "sender.json",
            "--input",
            "source.bin",
            "--attempts",
            "4"
        ])
        .unwrap()
        .command,
        Command::SendResumable { .. }
    ));
}

#[test]
fn completion_opens_one_absolute_proof_window_that_cannot_be_refreshed() {
    let initial = Retention::observe(None, 100, false, options());
    let completed = Retention::observe(Some(initial), 200, true, options());
    assert_eq!(
        completed,
        Retention::Committed {
            until: 5_000_000_200
        }
    );
    for now in [201, 5_000_000_199, 5_000_000_200, u64::MAX] {
        for reports_commit in [false, true] {
            assert_eq!(
                Retention::observe(Some(completed), now, reports_commit, options()),
                completed
            );
        }
    }
    assert_eq!(completed.expired(5_000_000_199), None);
    assert_eq!(
        completed.expired(5_000_000_200),
        Some("proof_recovery_expired")
    );
}

#[test]
fn incomplete_activity_renews_idle_time_but_does_not_claim_completion() {
    let initial = Retention::observe(None, 10, false, options());
    assert_eq!(
        initial.expired(10_000_000_010),
        Some("idle_retention_expired")
    );
    let later = Retention::observe(Some(initial), 1000, false, options());
    assert_eq!(
        later,
        Retention::Incomplete {
            until: 10_000_001_000
        }
    );
    assert_eq!(later.expired(10_000_000_010), None);
}

#[test]
fn deadline_overflow_saturates_instead_of_reopening_or_wrapping() {
    assert_eq!(deadline(u64::MAX - 1, 1), u64::MAX);
    assert_eq!(deadline(1, u64::MAX), u64::MAX);
    let retained = Retention::observe(None, u64::MAX - 1, true, options());
    assert_eq!(retained.expired(u64::MAX - 1), None);
    assert_eq!(retained.expired(u64::MAX), Some("proof_recovery_expired"));
}

#[test]
fn committed_without_proof_is_not_relabelled_as_success_or_rollback() {
    let receipt = receipt();
    let report = ResumeReport {
        outcome: Err(ResumeError::Transfer(LiveStreamError::Commit(Box::new(
            LiveStreamCommitError::CommittedWithoutProof {
                receipt: Box::new(receipt.clone()),
                source: Box::new(LiveStreamError::Timeout("final Proof")),
            },
        )))),
        prefix: Some(receipt.prefix.clone()),
        attempts: 2,
        receipt_reused: false,
        retained_epoch_bytes: 0,
        sink_written_bytes: 4,
        completed: Some(receipt.clone()),
    };
    let event = completion_event(
        &ResumeServiceCompletion {
            connection: 11,
            address: "127.0.0.1:1234".parse().unwrap(),
            session: Some(key()),
            outcome: ResumeServiceOutcome::Transfer(report),
        },
        None,
    );
    assert_eq!(event["transfer"]["status"], "committed_without_proof");
    assert!(event["transfer"]["receipt"].is_null());
    assert_eq!(
        event["transfer"]["completed_receipt"],
        receipt_json(&receipt)
    );
    assert_eq!(event["proof_write_confirmed"], false);
    assert_eq!(event["sender_receipt_observed"], false);
}

#[test]
fn refusal_projection_keeps_busy_retired_quota_and_factory_failures_distinct() {
    let cases = [
        (ResumeServiceRejection::Busy, "session_busy"),
        (ResumeServiceRejection::Retired, "session_retired"),
        (
            ResumeServiceRejection::Capacity("untrusted text must not escape"),
            "session_capacity_refused",
        ),
        (
            ResumeServiceRejection::AttemptsExhausted,
            "attempts_exhausted",
        ),
        (
            ResumeServiceRejection::Factory(
                io::Error::new(io::ErrorKind::StorageFull, "private path").into(),
            ),
            "retention_refused",
        ),
        (
            ResumeServiceRejection::Factory(
                io::Error::new(io::ErrorKind::PermissionDenied, "secret sink detail").into(),
            ),
            "factory_failed",
        ),
    ];
    for (rejection, status) in cases {
        let event = completion_event(
            &ResumeServiceCompletion {
                connection: 1,
                address: "127.0.0.1:1".parse().unwrap(),
                session: Some(key()),
                outcome: ResumeServiceOutcome::Rejected(rejection),
            },
            None,
        );
        assert_eq!(event["transfer"]["status"], status);
        assert_eq!(event["outcome_kind"], "rejected");
        assert_eq!(event["proof_write_confirmed"], false);
        let encoded = event.to_string();
        for private in ["untrusted text", "private path", "secret sink detail"] {
            assert!(!encoded.contains(private));
        }
    }
}

#[test]
fn failed_handshake_never_invents_an_authenticated_key_or_publication() {
    let event = completion_event(
        &ResumeServiceCompletion {
            connection: 0,
            address: "127.0.0.1:1".parse().unwrap(),
            session: None,
            outcome: ResumeServiceOutcome::Rejected(ResumeServiceRejection::Connection(
                ResumeError::Transfer(LiveStreamError::Tls(asupersync::tls::TlsError::Handshake(
                    "private diagnostic".to_owned(),
                ))),
            )),
        },
        None,
    );
    assert!(event["session"].is_null());
    assert!(event["publication"].is_null());
    assert_eq!(event["transfer"]["status"], "tls_failed");
    assert!(!event.to_string().contains("private diagnostic"));
}
