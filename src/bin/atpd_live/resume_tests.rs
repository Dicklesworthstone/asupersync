//! Focused policy and command regressions; native effects are covered by CLI tests.

use super::*;
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamPrefix, LiveStreamReceipt};
use clap::Parser;

#[test]
fn attempts_delay_and_proof_retention_have_explicit_finite_bounds() {
    for (attempts, delay, proof) in [(1, 1, 1), (1024, 60_000, 86_400)] {
        let options = Options::new(attempts, delay, proof).unwrap();
        assert_eq!(options.attempts, attempts);
        assert_eq!(options.retry_delay.as_millis(), u128::from(delay));
        assert_eq!(options.proof_recovery.as_secs(), proof);
    }
    for (attempts, delay, proof) in [
        (0, 1, 1),
        (1025, 1, 1),
        (1, 0, 1),
        (1, 60_001, 1),
        (1, 1, 0),
        (1, 1, 86_401),
        (u32::MAX, u64::MAX, u64::MAX),
    ] {
        assert!(Options::new(attempts, delay, proof).is_err());
    }
}

#[test]
fn sender_retries_network_failures_but_not_authority_or_local_failures() {
    for kind in [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::NetworkUnreachable,
    ] {
        assert!(sender_retryable(
            &LiveStreamError::Io(io::Error::from(kind)).into()
        ));
        assert!(sender_retryable(
            &LiveStreamError::Tls(TlsError::Io(io::Error::from(kind))).into()
        ));
    }
    assert!(sender_retryable(
        &LiveStreamError::Timeout("resume epoch acknowledgement").into()
    ));
    for error in [
        ResumeError::PeerIdentity,
        ResumeError::Continuity("untrusted offset"),
        ResumeError::LocalFailure,
        ResumeError::AttemptsExhausted,
        LiveStreamError::Tls(TlsError::Certificate("bad issuer".to_owned())).into(),
        LiveStreamError::Io(io::Error::from(io::ErrorKind::PermissionDenied)).into(),
        LiveStreamError::Protocol("wrong proof").into(),
        LiveStreamError::Cancelled(Some(CancelReason::user("stop"))).into(),
    ] {
        assert!(!sender_retryable(&error), "must refuse {error:?}");
    }
}

#[test]
fn refused_receiver_peers_do_not_recreate_a_sink_or_authorize_local_retry() {
    assert!(receiver_retryable(&ResumeError::PeerIdentity));
    assert!(receiver_retryable(&ResumeError::Continuity(
        "nonce changed"
    )));
    assert!(receiver_retryable(
        &LiveStreamError::Tls(TlsError::Certificate("unknown".to_owned())).into()
    ));
    for error in [
        ResumeError::LocalFailure,
        ResumeError::AttemptsExhausted,
        LiveStreamError::Io(io::Error::from(io::ErrorKind::StorageFull)).into(),
        LiveStreamError::TooLarge(10).into(),
        LiveStreamError::Cancelled(None).into(),
    ] {
        assert!(!receiver_retryable(&error));
    }
}

#[test]
fn proof_recovery_deadline_is_absolute_and_cannot_be_extended_by_reconnects() {
    let first = first_deadline(None, Time::from_nanos(10), Duration::from_nanos(100));
    assert_eq!(first.as_nanos(), 110);
    for now in [11, 100, 110, 1_000, u64::MAX] {
        assert_eq!(
            first_deadline(Some(first), Time::from_nanos(now), Duration::from_secs(5)),
            first
        );
    }
    let saturated = first_deadline(None, Time::from_nanos(u64::MAX - 1), Duration::from_secs(1));
    assert_eq!(saturated.as_nanos(), u64::MAX);
}

fn receipt() -> LiveStreamReceipt {
    LiveStreamReceipt {
        prefix: LiveStreamPrefix {
            stream_nonce: [1; 32],
            epochs: 1,
            bytes: 4,
            chain: [2; 32],
        },
        source_sha256: [3; 32],
    }
}

#[test]
fn failed_proof_keeps_a_local_receipt_without_claiming_received_proof() {
    let committed = receipt();
    let report = ResumeReport {
        outcome: Err(LiveStreamError::Commit(Box::new(
            LiveStreamCommitError::CommittedWithoutProof {
                receipt: Box::new(committed.clone()),
                source: Box::new(LiveStreamError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "secret-peer-payload",
                ))),
            },
        ))
        .into()),
        prefix: Some(committed.prefix.clone()),
        attempts: 2,
        receipt_reused: false,
        retained_epoch_bytes: 0,
        sink_written_bytes: 4,
        completed: Some(committed.clone()),
    };
    let json = report_json(&report);
    assert_eq!(json["status"], "committed_without_proof");
    assert!(json["receipt"].is_null());
    assert_eq!(json["completed_receipt"], receipt_json(&committed));
    assert!(!json.to_string().contains("secret-peer-payload"));
    assert!(receiver_retryable(report.outcome.as_ref().unwrap_err()));
    assert!(!sender_retryable(report.outcome.as_ref().unwrap_err()));
}

#[test]
fn failed_application_commit_is_never_retry_permission() {
    let error = ResumeError::from(LiveStreamError::Commit(Box::new(
        LiveStreamCommitError::Unconfirmed {
            receipt: Box::new(receipt()),
            interruption: Some(Box::new(LiveStreamError::Timeout("sink commit"))),
            source: io::Error::from(io::ErrorKind::ConnectionReset),
        },
    )));
    assert!(!sender_retryable(&error));
    assert!(!receiver_retryable(&error));
}

#[test]
fn resumable_commands_require_explicit_attempt_permission_without_changing_legacy_commands() {
    use super::super::{Cli, Command};
    let command =
        Cli::try_parse_from(["atpd-live", "send", "--config", "s.json", "--input", "data"])
            .unwrap();
    assert!(matches!(command.command, Command::Send { .. }));
    let command = Cli::try_parse_from(["atpd-live", "serve", "--config", "r.json"]).unwrap();
    assert!(matches!(command.command, Command::Serve { .. }));
    assert!(
        Cli::try_parse_from([
            "atpd-live",
            "send-resumable",
            "--config",
            "s.json",
            "--input",
            "data"
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["atpd-live", "receive-resumable", "--config", "r.json"]).is_err());
    let command = Cli::try_parse_from([
        "atpd-live",
        "send-resumable",
        "--config",
        "s.json",
        "--input",
        "data",
        "--attempts",
        "4",
    ])
    .unwrap();
    assert!(matches!(
        command.command,
        Command::SendResumable {
            attempts: 4,
            retry_delay_ms: 250,
            ..
        }
    ));
    let command = Cli::try_parse_from([
        "atpd-live",
        "receive-resumable",
        "--config",
        "r.json",
        "--attempts",
        "4",
    ])
    .unwrap();
    assert!(matches!(
        command.command,
        Command::ReceiveResumable {
            attempts: 4,
            proof_recovery_secs: 30,
            ..
        }
    ));
}
