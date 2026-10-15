//! Explicit command selection and independent storage/delivery observations.
use super::super::{Cli, Command};
use super::*;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::finalization::FinalProofPersistError;
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamPrefix, LiveStreamReceipt};
use clap::Parser;

fn receipt() -> LiveStreamReceipt {
    LiveStreamReceipt {
        prefix: LiveStreamPrefix {
            stream_nonce: [1; 32],
            epochs: 1,
            bytes: 3,
            chain: [2; 32],
        },
        source_sha256: [3; 32],
    }
}
fn report(outcome: Result<LiveStreamReceipt, ResumeError>) -> ResumeReport {
    ResumeReport {
        outcome,
        prefix: Some(receipt().prefix),
        attempts: 1,
        receipt_reused: false,
        retained_epoch_bytes: 0,
        sink_written_bytes: 0,
        completed: None,
    }
}

#[test]
fn checkpoint_commands_require_intent_path_and_explicit_attempt_permission() {
    let upload = [
        "atpd-live",
        "send-checkpointed",
        "--config",
        "sender.json",
        "--input",
        "input.bin",
        "--checkpoint",
        "/private/intent",
        "--attempts",
        "3",
    ];
    assert!(matches!(
        Cli::try_parse_from(upload).unwrap().command,
        Command::SendCheckpointed { .. }
    ));
    assert!(Cli::try_parse_from(&upload[..upload.len() - 2]).is_err());
    assert!(
        Cli::try_parse_from([
            "atpd-live",
            "send-checkpointed",
            "--config",
            "sender.json",
            "--input",
            "input.bin",
            "--attempts",
            "1"
        ])
        .is_err()
    );
    let recovery = [
        "atpd-live",
        "recover-proof",
        "--config",
        "sender.json",
        "--checkpoint",
        "/private/intent",
        "--attempts",
        "3",
    ];
    assert!(matches!(
        Cli::try_parse_from(recovery).unwrap().command,
        Command::RecoverProof { .. }
    ));
    assert!(
        Cli::try_parse_from(recovery.into_iter().chain(["--input", "must-not-be-read"])).is_err()
    );
}

#[test]
fn legacy_commands_do_not_silently_enable_checkpointing() {
    assert!(matches!(
        Cli::try_parse_from([
            "atpd-live",
            "send-resumable",
            "--config",
            "s.json",
            "--input",
            "i.bin",
            "--attempts",
            "1"
        ])
        .unwrap()
        .command,
        Command::SendResumable { .. }
    ));
    assert!(matches!(
        Cli::try_parse_from([
            "atpd-live",
            "send",
            "--config",
            "s.json",
            "--input",
            "i.bin"
        ])
        .unwrap()
        .command,
        Command::Send { .. }
    ));
}

#[test]
fn attempt_and_delay_bounds_are_finite_and_independent() {
    for (attempts, retry_delay_ms) in [(1, 1), (1024, 60_000)] {
        assert!(
            Options {
                attempts,
                retry_delay_ms
            }
            .validate()
            .is_ok()
        );
    }
    for (attempts, retry_delay_ms) in [(0, 1), (1025, 1), (1, 0), (1, 60_001), (u32::MAX, u64::MAX)]
    {
        assert!(
            Options {
                attempts,
                retry_delay_ms
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn successful_storage_after_timeout_is_not_a_delivery_receipt_or_retry_permission() {
    let failed = ResumeError::Checkpoint(Box::new(FinalProofPersistError {
        stored: true,
        interruption: Some(Box::new(LiveStreamError::Timeout(
            "sender final checkpoint",
        ))),
        source: None,
    }));
    assert!(!retryable(&failed));
    let value = transfer_json(&report(Err(failed)));
    assert_eq!(value["status"], "checkpoint_blocked");
    assert!(value["receipt"].is_null());
    assert!(value["completed_receipt"].is_null());
    assert_eq!(value["persistence"]["stored"], true);
    assert_eq!(value["persistence"]["interruption"], "timeout");
    assert_eq!(value["persistence"]["storage_failed"], false);
}

#[test]
fn simultaneous_storage_error_and_cancellation_remain_separate_without_private_text() {
    let error = ResumeError::Checkpoint(Box::new(FinalProofPersistError {
        stored: false,
        interruption: Some(Box::new(LiveStreamError::Cancelled(Some(
            CancelReason::user("private reason"),
        )))),
        source: Some(io::Error::other("private checkpoint path")),
    }));
    assert!(!retryable(&error));
    let value = transfer_json(&report(Err(error)));
    assert_eq!(value["persistence"]["storage_failed"], true);
    assert_eq!(value["persistence"]["interruption"], "cancelled");
    assert!(!value.to_string().contains("private"));
}

#[test]
fn only_transport_failures_are_retryable_and_only_proof_is_success() {
    assert!(retryable(&ResumeError::Transfer(LiveStreamError::Io(
        io::Error::from(io::ErrorKind::ConnectionReset)
    ))));
    for error in [
        ResumeError::LocalFailure,
        ResumeError::AttemptsExhausted,
        ResumeError::PeerIdentity,
        ResumeError::Continuity("peer changed state"),
        ResumeError::Transfer(LiveStreamError::Tls(TlsError::Handshake(
            "private certificate".into(),
        ))),
    ] {
        assert!(!retryable(&error));
    }
    let exact = receipt();
    let mut success = report(Ok(exact.clone()));
    success.completed = Some(exact.clone());
    let value = transfer_json(&success);
    assert_eq!(value["status"], "complete");
    assert_eq!(value["receipt"], receipt_json(&exact));
    assert_eq!(value["completed_receipt"], value["receipt"]);
}
