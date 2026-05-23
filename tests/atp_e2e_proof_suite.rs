//! ATP-N3: End-to-End Proof Suite Integration Test
//!
//! Main integration test file for ATP e2e proof suite.

mod atp;

use asupersync::lab::crashpack::{
    AtpEvidenceLedger, AtpReplayCoordinator, AtpTransferOracle, AtpTransferState, CrashpackBuilder,
    TraceMinimizer, TraceMinimizerConfig, TransferOracleResult, TransferViolation,
    ViolationSeverity,
};
use asupersync::lab::oracle::OracleStats;
use asupersync::lab::oracle::evidence::{
    BayesFactor, EvidenceEntry, EvidenceLine, EvidenceStrength, LogLikelihoodContributions,
};
use asupersync::trace::{TraceBuffer, TraceEvent};
use asupersync::types::Time;
use atp::{
    AtpCrashPoint, AtpForensics, AtpObligationTracker, ChunkRangeInfo, FaultConfig, FaultInjector,
    FaultPoint, FaultType, JournalOffsets, ObjectInfo, ObligationType, ReproducibleTestCase,
    VerifierDecision,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_atp_e2e_proof_suite_integration() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize test components
    let temp_dir = TempDir::new()?;
    let mut forensics = AtpForensics::new(temp_dir.path())?;
    let tracker = std::sync::Arc::new(AtpObligationTracker::new());
    let fault_injector = FaultInjector::new();

    // Configure fault injection for crash testing
    fault_injector.configure_fault(FaultConfig {
        point: FaultPoint::JournalAppend,
        fault_type: FaultType::Crash,
        probability: 0.1, // 10% chance to trigger
        trigger_count: None,
    });

    // Start forensics capture
    forensics.start_capture(
        "integration_test",
        "Testing ATP e2e proof suite",
        "integration",
    );

    // Create test obligation
    let obligation_id = tracker.create_obligation(
        ObligationType::Transfer("test_transfer".to_string()),
        "integration_test".to_string(),
        HashMap::new(),
    );

    // Record test data for forensics
    forensics.record_manifest_root("integration_test_root");

    // Simulate successful operation (no crash injection)
    fault_injector.set_enabled(false);

    // Fulfill obligation
    tracker.fulfill_obligation(&obligation_id);

    // Validate no leaks
    let leaks = tracker.check_for_leaks(std::time::Duration::from_secs(1));
    assert!(leaks.is_empty(), "No obligation leaks should occur");

    // Validate region quiescence
    tracker.validate_region_quiescence()?;

    // Finish forensics capture
    let _artifact_path = forensics.finish_capture()?;

    Ok(())
}

#[test]
fn test_atp_crash_matrix_basic() -> Result<(), Box<dyn std::error::Error>> {
    for crash_point in AtpCrashPoint::ALL {
        let fault_injector = FaultInjector::new();
        let fault_point = crash_point.fault_point();

        assert!(
            fault_injector.should_inject(&fault_point).is_none(),
            "unconfigured crash point {crash_point:?} unexpectedly injected {fault_point:?}"
        );

        fault_injector.inject_crash_at(crash_point.as_str());
        let observed_fault = fault_injector.should_inject(&fault_point);
        assert!(
            matches!(observed_fault, Some(FaultType::Crash)),
            "configured crash point {crash_point:?} did not trigger {fault_point:?}: {observed_fault:?}"
        );
    }

    Ok(())
}

#[test]
fn test_atp_forensics_basic() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let mut forensics = AtpForensics::new(temp_dir.path())?;

    forensics.start_capture("test_failure", "Test forensics capture", "test_operation");
    forensics.record_manifest_root("test_manifest_root_123");
    forensics.set_crash_point("post_fsync");
    forensics.record_journal_offsets(JournalOffsets {
        last_written: 128,
        last_flushed: 128,
        last_committed: 96,
        recovery_checkpoint: 64,
    })?;
    forensics.record_chunk_range(ChunkRangeInfo {
        start_offset: 64,
        length: 64,
        chunk_hash: "sha256:test-chunk".to_string(),
        state: "verified".to_string(),
        verified: true,
    });
    forensics.record_verifier_decision(VerifierDecision {
        stage: "ChunkHash".to_string(),
        target: "test-object:1".to_string(),
        decision: "accepted".to_string(),
        reason: Some("digest matched".to_string()),
        timestamp: 7,
    });
    forensics.set_object_info(ObjectInfo {
        object_id: "test-object".to_string(),
        object_kind: "file".to_string(),
        size: 128,
        metadata: BTreeMap::from([("content_type".to_string(), serde_json::json!("test"))]),
    });
    forensics.set_test_case(ReproducibleTestCase {
        test_function: "test_atp_forensics_basic".to_string(),
        parameters: BTreeMap::from([
            ("seed".to_string(), serde_json::json!(1234)),
            ("crash_point".to_string(), serde_json::json!("post_fsync")),
            ("diagnostic_noise".to_string(), serde_json::json!("drop-me")),
        ]),
        random_seed: 1234,
        lab_config: None,
        reproduction_steps: Vec::new(),
    });

    let artifact_path = forensics.finish_capture()?;
    assert!(artifact_path.exists());

    let loaded_artifact = AtpForensics::load_artifact(&artifact_path)?;
    assert_eq!(loaded_artifact.context.failure_type, "test_failure");
    assert_eq!(
        loaded_artifact.manifest_root.as_deref(),
        Some("test_manifest_root_123")
    );
    assert_eq!(
        loaded_artifact.context.crash_point.as_deref(),
        Some("post_fsync")
    );
    assert_eq!(loaded_artifact.chunk_ranges.len(), 1);
    assert_eq!(loaded_artifact.verifier_decisions.len(), 1);
    assert_eq!(loaded_artifact.journal_offsets.last_written, 128);
    assert_eq!(loaded_artifact.journal_offsets.last_committed, 96);
    assert_eq!(loaded_artifact.journal_offsets.recovery_checkpoint, 64);

    let replay_command = AtpForensics::generate_replay_command(&loaded_artifact);
    assert!(replay_command.contains("test_atp_forensics_basic"));
    assert!(replay_command.contains("--seed 1234"));
    assert!(replay_command.contains(&loaded_artifact.artifact_id));

    let mut minimizer = AtpForensics::create_minimizer(&loaded_artifact);
    let minimized = minimizer.minimize()?;
    assert_eq!(minimized.random_seed, 1234);
    assert!(minimized.parameters.contains_key("crash_point"));
    assert!(!minimized.parameters.contains_key("diagnostic_noise"));
    assert!(
        minimized
            .reproduction_steps
            .iter()
            .any(|step| step.contains("inject crash at post_fsync")),
        "minimized reproduction did not preserve crash point: {:?}",
        minimized.reproduction_steps
    );
    Ok(())
}

#[test]
fn test_atp_replay_rejects_violation_crashpack_without_trace_witness() {
    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("manifest_integrity"))
        .build()
        .expect("crashpack builds");

    let err = AtpReplayCoordinator::new(crashpack)
        .replay()
        .expect_err("violation crashpack without trace must fail closed");

    assert!(
        err.to_string().contains("no trace events"),
        "unexpected replay error: {err}"
    );
}

#[test]
fn test_atp_replay_minimizer_preserves_failure_witness() {
    let events = vec![
        TraceEvent::user_trace(1, Time::from_nanos(1), "setup event"),
        TraceEvent::user_trace(2, Time::from_nanos(2), "ATP violation: manifest corruption"),
        TraceEvent::user_trace(3, Time::from_nanos(3), "noise after failure"),
    ];
    let minimizer = TraceMinimizer::new(TraceMinimizerConfig {
        enabled: true,
        reduction_target: 0.9,
        max_attempts: 16,
        preserve_oracle_events: true,
        preserve_timing: false,
    });

    let minimized = minimizer.minimize(&events).expect("minimization succeeds");

    assert!(
        minimized.minimized_events.len() < events.len(),
        "noise events should be removable"
    );
    assert!(
        minimized
            .minimized_events
            .iter()
            .any(|event| event.to_string().contains("manifest corruption")),
        "failure witness must be retained"
    );
}

#[test]
fn test_atp_replay_accepts_violation_crashpack_with_trace_witness() {
    let mut trace = TraceBuffer::new(4);
    trace.push(TraceEvent::user_trace(
        1,
        Time::from_nanos(1),
        "ATP violation: proof bundle invalid",
    ));
    trace.push(TraceEvent::user_trace(
        2,
        Time::from_nanos(2),
        "diagnostic noise",
    ));

    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("proof_bundle_validity"))
        .with_trace(trace)
        .build()
        .expect("crashpack builds");
    let result = AtpReplayCoordinator::new(crashpack)
        .with_minimizer_config(TraceMinimizerConfig {
            enabled: true,
            reduction_target: 0.5,
            max_attempts: 8,
            preserve_oracle_events: true,
            preserve_timing: false,
        })
        .replay()
        .expect("witnessed violation crashpack replays structurally");

    assert_eq!(result.original_violations, 1);
    assert!(result.replay_successful);
    assert_eq!(result.minimized_trace_length, 1);
    assert_eq!(result.oracle_results.len(), 1);

    let replay_report = &result.oracle_results[0];
    assert_eq!(replay_report.total, 1);
    assert_eq!(replay_report.passed, 0);
    assert_eq!(replay_report.failed, 1);
    assert_eq!(replay_report.check_time_nanos, 0);
    let replay_entry = replay_report
        .entry("proof_bundle_validity")
        .expect("replay report preserves proof oracle entry");
    assert!(!replay_entry.passed);
    assert_eq!(replay_entry.stats.entities_tracked, 1);
    assert_eq!(replay_entry.stats.events_recorded, 1);
    assert!(
        replay_entry
            .violation
            .as_deref()
            .is_some_and(|text| text.contains("proof_bundle_validity failed")),
        "replay report should preserve violation summary"
    );
}

#[test]
fn test_atp_replay_rejects_unrelated_failure_witness() {
    let mut trace = TraceBuffer::new(4);
    trace.push(TraceEvent::user_trace(
        1,
        Time::from_nanos(1),
        "ATP violation: manifest corruption",
    ));

    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("proof_bundle_validity"))
        .with_trace(trace)
        .build()
        .expect("crashpack builds");

    let err = AtpReplayCoordinator::new(crashpack)
        .replay()
        .expect_err("unrelated trace failure must not satisfy proof-bundle replay");

    assert!(
        err.to_string()
            .contains("without matching trace failure witnesses: proof_bundle_validity"),
        "unexpected replay error: {err}"
    );
}

#[test]
fn test_atp_replay_command_sanitizes_seed_and_oracle_env_names() {
    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("proof-bundle.validity"))
        .with_seed("lab-seed.v1", 42)
        .build()
        .expect("crashpack builds");

    let command = AtpReplayCoordinator::new(crashpack)
        .generate_replay_command(PathBuf::from("artifacts with space").as_path())
        .expect("replay command renders");

    assert!(command.contains("export ATP_SEED_LAB_SEED_V1=42"));
    assert!(command.contains("export ATP_ORACLE_PROOF_BUNDLE_VALIDITY=enabled"));
    assert!(command.contains(
        "asupersync atp replay --trace-file 'artifacts with space/transfer.atp-trace' --manifest 'artifacts with space/manifest'"
    ));
    assert!(command.contains("--journal-digest 'artifacts with space/journal.digest'"));
    assert!(command.contains("--evidence-ledger 'artifacts with space/evidence-ledger.json'"));
    assert!(command.contains("--pathlog 'artifacts with space/pathlog'"));
    assert!(command.contains("--quiclog 'artifacts with space/quiclog'"));
    assert!(command.contains("--repairlog 'artifacts with space/repairlog'"));
    assert!(command.contains("--validate-oracles"));
    assert!(!command.contains("--trace-file artifacts with space"));
}

#[test]
fn test_atp_crashpack_emits_required_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let mut trace = TraceBuffer::new(8);
    trace.push(TraceEvent::user_trace(
        1,
        Time::from_nanos(1),
        "ATP path selected: relay route",
    ));
    trace.push(TraceEvent::user_trace(
        2,
        Time::from_nanos(2),
        "QUIC UDP packet loss observed",
    ));
    trace.push(TraceEvent::user_trace(
        3,
        Time::from_nanos(3),
        "repair RaptorQ symbol recovered",
    ));
    trace.push(TraceEvent::user_trace(
        4,
        Time::from_nanos(4),
        "ATP violation: manifest_integrity",
    ));

    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("manifest_integrity"))
        .with_trace(trace)
        .with_seed("lab-seed", 42)
        .with_artifact_path("artifacts/pathlog")
        .with_artifact_path("artifacts/pathlog")
        .with_metadata("transfer_id", "tx-emit")
        .build()
        .expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let replay_report = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())?;
    assert!(replay_report.replay_ready);
    assert_eq!(replay_report.trace_events, 4);
    assert_eq!(replay_report.ledger_entries, 1);
    assert_eq!(replay_report.violation_entries, 1);

    for artifact in [
        "transfer.atp-trace",
        "manifest",
        "journal",
        "journal.digest",
        "evidence-ledger.json",
        "pathlog",
        "quiclog",
        "repairlog",
        "replay_command.sh",
    ] {
        assert!(
            temp_dir.path().join(artifact).exists(),
            "expected emitted artifact {artifact}"
        );
    }

    let journal = std::fs::read_to_string(temp_dir.path().join("journal"))?;
    let expected_journal_digest =
        format!("sha256:{}", hex::encode(Sha256::digest(journal.as_bytes())));

    let manifest = std::fs::read_to_string(temp_dir.path().join("manifest"))?;
    assert!(manifest.contains("schema_version: 1"));
    assert!(manifest.contains("violations: 1"));
    assert!(manifest.contains(&format!("journal_digest: {expected_journal_digest}")));
    assert!(manifest.contains("journal_digest_artifact: journal.digest"));
    assert!(manifest.contains("evidence_ledger: evidence-ledger.json"));
    assert!(manifest.contains("metadata.transfer_id: tx-emit"));
    assert!(manifest.contains("seeds:"));
    assert!(manifest.contains("lab-seed: 42"));
    assert!(manifest.contains("artifact_paths:"));
    assert_eq!(
        manifest.matches("artifacts/pathlog").count(),
        1,
        "artifact paths should be de-duplicated"
    );

    let journal_digest = std::fs::read_to_string(temp_dir.path().join("journal.digest"))?;
    assert!(journal_digest.contains(&format!("digest: {expected_journal_digest}")));
    assert!(journal_digest.contains(&format!("bytes: {}", journal.len())));
    assert_eq!(replay_report.journal_digest, expected_journal_digest);

    let evidence_ledger = std::fs::read_to_string(temp_dir.path().join("evidence-ledger.json"))?;
    let evidence_ledger =
        AtpEvidenceLedger::import_json(&evidence_ledger).expect("evidence ledger imports");
    assert_eq!(evidence_ledger.schema_version, 1);
    assert_eq!(evidence_ledger.seeds.get("lab-seed"), Some(&42));
    assert_eq!(
        evidence_ledger.metadata.get("transfer_id"),
        Some(&"tx-emit".to_string())
    );
    assert_eq!(evidence_ledger.entries.len(), 1);
    assert_eq!(evidence_ledger.entries[0].oracle_name, "manifest_integrity");
    assert_eq!(evidence_ledger.entries[0].timestamp, 0);
    assert!(!evidence_ledger.entries[0].evidence.passed);
    assert_eq!(
        evidence_ledger.entries[0].artifact_path,
        Some(PathBuf::from("transfer.atp-trace"))
    );
    assert!(
        evidence_ledger
            .artifact_paths
            .contains(&PathBuf::from("evidence-ledger.json"))
    );
    assert!(
        evidence_ledger
            .artifact_paths
            .contains(&PathBuf::from("artifacts/pathlog"))
    );
    assert_eq!(
        evidence_ledger
            .artifact_paths
            .iter()
            .filter(|path| path.as_path() == std::path::Path::new("artifacts/pathlog"))
            .count(),
        1,
        "evidence ledger artifact paths should be de-duplicated"
    );
    assert_eq!(evidence_ledger.evidence_summary().strong, 1);

    assert!(journal.contains("oracle: manifest_integrity"));
    assert!(journal.contains("type: manifest_integrity"));
    assert!(journal.contains("severity: High"));
    assert!(journal.contains("source: test"));

    let replay_command = std::fs::read_to_string(temp_dir.path().join("replay_command.sh"))?;
    assert!(replay_command.contains("export ATP_SEED_LAB_SEED=42"));
    assert!(
        replay_command
            .contains("asupersync atp replay --trace-file transfer.atp-trace --manifest manifest")
    );
    assert!(replay_command.contains("--journal-digest journal.digest"));
    assert!(replay_command.contains("--evidence-ledger evidence-ledger.json"));
    assert!(replay_command.contains("--pathlog pathlog"));
    assert!(replay_command.contains("--quiclog quiclog"));
    assert!(replay_command.contains("--repairlog repairlog"));
    assert!(replay_command.contains("--validate-oracles"));
    assert!(replay_command.contains("--oracle manifest_integrity"));

    let pathlog = std::fs::read_to_string(temp_dir.path().join("pathlog"))?;
    assert!(pathlog.contains("relay route"));
    let quiclog = std::fs::read_to_string(temp_dir.path().join("quiclog"))?;
    assert!(quiclog.contains("QUIC UDP packet loss"));
    let repairlog = std::fs::read_to_string(temp_dir.path().join("repairlog"))?;
    assert!(repairlog.contains("RaptorQ symbol"));

    Ok(())
}

#[test]
fn test_atp_replay_from_emitted_artifacts_reproduces_journal_violations() {
    let temp_dir = TempDir::new().expect("tempdir is available");
    let mut trace = TraceBuffer::new(8);
    trace.push(TraceEvent::user_trace(
        1,
        Time::from_nanos(1),
        "setup event",
    ));
    trace.push(TraceEvent::user_trace(
        2,
        Time::from_nanos(2),
        "ATP violation: manifest integrity failure",
    ));
    trace.push(TraceEvent::user_trace(
        3,
        Time::from_nanos(3),
        "ATP violation: journal consistency failure",
    ));
    trace.push(TraceEvent::user_trace(
        4,
        Time::from_nanos(4),
        "diagnostic noise after transfer",
    ));

    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(TransferOracleResult {
            oracle_name: "transfer_integrity".to_string(),
            violations: vec![
                transfer_violation(
                    "manifest_integrity",
                    "manifest integrity failed",
                    ViolationSeverity::High,
                ),
                transfer_violation(
                    "journal_consistency",
                    "journal consistency failed",
                    ViolationSeverity::Medium,
                ),
            ],
            stats: OracleStats {
                entities_tracked: 2,
                events_recorded: 4,
            },
            passed: false,
        })
        .with_trace(trace)
        .with_seed("lab-seed", 99)
        .with_metadata("transfer_id", "tx-replay-from-artifacts")
        .build()
        .expect("crashpack builds");

    crashpack
        .emit_atp_trace(temp_dir.path())
        .expect("crashpack emits replay artifacts");

    let result = AtpReplayCoordinator::replay_from_artifacts_with_config(
        temp_dir.path(),
        TraceMinimizerConfig {
            enabled: true,
            reduction_target: 0.8,
            max_attempts: 16,
            preserve_oracle_events: true,
            preserve_timing: false,
        },
    )
    .expect("emitted artifacts replay");

    assert_eq!(result.original_violations, 2);
    assert!(result.replay_successful);
    assert_eq!(result.minimized_trace_length, 2);
    assert_eq!(result.oracle_results.len(), 1);

    let replay_report = &result.oracle_results[0];
    assert_eq!(replay_report.total, 1);
    assert_eq!(replay_report.passed, 0);
    assert_eq!(replay_report.failed, 1);
    let replay_entry = replay_report
        .entry("transfer_integrity")
        .expect("replay report preserves journal oracle");
    assert!(!replay_entry.passed);
    let violation_summary = replay_entry
        .violation
        .as_deref()
        .expect("journal violations should be reported");
    assert!(violation_summary.contains("manifest_integrity"));
    assert!(violation_summary.contains("journal_consistency"));
}

#[test]
fn test_atp_replay_artifacts_require_trace_witnesses() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("manifest_integrity"))
        .build()
        .expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let err = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())
        .expect_err("violation replay artifacts without trace witnesses must fail closed");
    assert!(
        err.to_string().contains("no trace failure witnesses"),
        "unexpected replay artifact validation error: {err}"
    );

    Ok(())
}

#[test]
fn test_atp_replay_artifacts_reject_ledger_that_masks_journal_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let mut trace = TraceBuffer::new(4);
    trace.push(TraceEvent::user_trace(
        1,
        Time::from_nanos(1),
        "ATP violation: manifest_integrity failure",
    ));
    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("manifest_integrity"))
        .with_trace(trace)
        .with_seed("lab-seed", 101)
        .build()
        .expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let ledger_path = temp_dir.path().join("evidence-ledger.json");
    let ledger_json = std::fs::read_to_string(&ledger_path)?;
    let mut ledger: serde_json::Value = serde_json::from_str(&ledger_json)?;
    ledger["entries"][0]["evidence"]["passed"] = serde_json::Value::Bool(true);
    std::fs::write(&ledger_path, serde_json::to_string_pretty(&ledger)?)?;

    let err = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())
        .expect_err("ledger cannot contradict a failed journal oracle");
    assert!(
        err.to_string().contains("passed status mismatch"),
        "unexpected replay artifact validation error: {err}"
    );

    Ok(())
}

#[test]
fn test_atp_replay_artifacts_reject_ledger_entry_detached_from_trace_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let mut trace = TraceBuffer::new(4);
    trace.push(TraceEvent::user_trace(
        1,
        Time::from_nanos(1),
        "ATP violation: manifest_integrity failure",
    ));
    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("manifest_integrity"))
        .with_trace(trace)
        .with_seed("lab-seed", 102)
        .build()
        .expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let ledger_path = temp_dir.path().join("evidence-ledger.json");
    let ledger_json = std::fs::read_to_string(&ledger_path)?;
    let mut ledger: serde_json::Value = serde_json::from_str(&ledger_json)?;
    ledger["entries"][0]["artifact_path"] = serde_json::Value::String("pathlog".to_string());
    std::fs::write(&ledger_path, serde_json::to_string_pretty(&ledger)?)?;

    let err = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())
        .expect_err("ledger entry evidence must remain attached to trace artifact");
    assert!(
        err.to_string().contains("artifact path mismatch"),
        "unexpected replay artifact validation error: {err}"
    );

    Ok(())
}

#[test]
fn test_atp_replay_artifacts_reject_manifest_metadata_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let crashpack = CrashpackBuilder::new()
        .with_metadata("transfer_id", "tx-manifest")
        .build()
        .expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let manifest_path = temp_dir.path().join("manifest");
    let manifest = std::fs::read_to_string(&manifest_path)?;
    std::fs::write(
        &manifest_path,
        manifest.replace(
            "metadata.transfer_id: tx-manifest",
            "metadata.transfer_id: tx-drift",
        ),
    )?;

    let err = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())
        .expect_err("manifest metadata must remain bound to evidence ledger metadata");
    assert!(
        err.to_string().contains("manifest metadata mismatch"),
        "unexpected replay artifact validation error: {err}"
    );

    Ok(())
}

#[test]
fn test_atp_replay_artifacts_reject_manifest_seed_drift() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = TempDir::new()?;
    let crashpack = CrashpackBuilder::new()
        .with_seed("lab-seed", 123)
        .build()
        .expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let manifest_path = temp_dir.path().join("manifest");
    let manifest = std::fs::read_to_string(&manifest_path)?;
    std::fs::write(
        &manifest_path,
        manifest.replace("  lab-seed: 123", "  lab-seed: 124"),
    )?;

    let err = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())
        .expect_err("manifest seeds must remain bound to evidence ledger seeds");
    assert!(
        err.to_string().contains("manifest seed mismatch"),
        "unexpected replay artifact validation error: {err}"
    );

    Ok(())
}

#[test]
fn test_atp_replay_artifacts_reject_replay_command_detached_from_log_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let crashpack = CrashpackBuilder::new().build().expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let replay_command_path = temp_dir.path().join("replay_command.sh");
    let replay_command = std::fs::read_to_string(&replay_command_path)?;
    std::fs::write(
        &replay_command_path,
        replay_command.replace("--pathlog pathlog", "--pathlog stale-pathlog"),
    )?;

    let err = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())
        .expect_err("replay command must keep pathlog bound to emitted artifact");
    assert!(
        err.to_string().contains("flag --pathlog mismatch"),
        "unexpected replay artifact validation error: {err}"
    );

    Ok(())
}

#[test]
fn test_atp_replay_artifacts_reject_specialized_log_projection_drift()
-> Result<(), Box<dyn std::error::Error>> {
    for artifact in ["pathlog", "quiclog", "repairlog"] {
        let temp_dir = TempDir::new()?;
        let mut trace = TraceBuffer::new(8);
        trace.push(TraceEvent::user_trace(
            1,
            Time::from_nanos(1),
            "ATP path selected: relay route",
        ));
        trace.push(TraceEvent::user_trace(
            2,
            Time::from_nanos(2),
            "QUIC UDP packet loss observed",
        ));
        trace.push(TraceEvent::user_trace(
            3,
            Time::from_nanos(3),
            "repair RaptorQ symbol recovered",
        ));

        let crashpack = CrashpackBuilder::new()
            .with_trace(trace)
            .build()
            .expect("crashpack builds");

        crashpack.emit_atp_trace(temp_dir.path())?;

        std::fs::write(
            temp_dir.path().join(artifact),
            format!("detached stale {artifact}\n"),
        )?;

        let err = AtpReplayCoordinator::validate_replay_artifacts(temp_dir.path())
            .expect_err("specialized log must remain derived from transfer.atp-trace");
        assert!(
            err.to_string().contains(&format!("{artifact} mismatch")),
            "unexpected replay artifact validation error for {artifact}: {err}"
        );
    }

    Ok(())
}

#[test]
fn test_atp_crashpack_quotes_oracle_replay_args() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let crashpack = CrashpackBuilder::new()
        .with_oracle_result(violation_result("manifest integrity's check"))
        .with_seed("lab seed", 7)
        .build()
        .expect("crashpack builds");

    crashpack.emit_atp_trace(temp_dir.path())?;

    let replay_command = std::fs::read_to_string(temp_dir.path().join("replay_command.sh"))?;
    assert!(replay_command.contains("export ATP_SEED_LAB_SEED=7"));
    assert!(replay_command.contains("--oracle 'manifest integrity'\"'\"'s check'"));
    assert!(!replay_command.contains("--oracle manifest integrity"));

    Ok(())
}

#[test]
fn test_atp_evidence_ledger_records_deterministic_artifact_metadata() {
    let mut ledger = AtpEvidenceLedger::new();
    let artifact_path = PathBuf::from("artifacts/transfer.atp-trace");

    ledger.record_seed("lab", 0xA7);
    ledger.add_metadata("transfer_id", "tx-ledger");
    ledger.record_oracle_result(
        "manifest_integrity",
        ledger_evidence("manifest_integrity", true, -2.0),
        Some(artifact_path.clone()),
    );
    ledger.record_oracle_result_at(
        "proof_bundle_validity",
        ledger_evidence("proof_bundle_validity", false, 2.5),
        Some(artifact_path.clone()),
        99,
    );

    let summary = ledger.evidence_summary();
    assert_eq!(ledger.entries[0].timestamp, 0);
    assert_eq!(ledger.entries[1].timestamp, 99);
    assert_eq!(ledger.artifact_paths, vec![artifact_path]);
    assert_eq!(ledger.seeds.get("lab"), Some(&0xA7));
    assert_eq!(summary.total, 2);
    assert_eq!(summary.against, 1);
    assert_eq!(summary.very_strong, 1);
    assert_eq!(summary.violation_count(), 1);
    assert!(summary.has_strong_violations());

    let json = ledger.export_json().expect("ledger exports as JSON");
    let roundtrip = AtpEvidenceLedger::import_json(&json).expect("ledger imports from JSON");
    assert_eq!(roundtrip.entries.len(), 2);
    assert_eq!(roundtrip.entries[0].timestamp, 0);
    assert_eq!(roundtrip.entries[1].timestamp, 99);
    assert_eq!(
        roundtrip.metadata.get("transfer_id"),
        Some(&"tx-ledger".to_string())
    );
}

#[test]
fn test_atp_transfer_oracle_records_final_exposure_and_cancellation_drain_violations() {
    let mut state = AtpTransferState::clean();
    state.unverified_final_exposures = 1;
    state.pending_cancellation_drains = 2;

    let result = AtpTransferOracle::new("atp_l2_oracle_surface").validate(&state);

    assert!(!result.passed);
    assert_eq!(result.stats.events_recorded, 8);
    assert_eq!(result.stats.entities_tracked, 2);

    let final_exposure = result
        .evidence_ledger
        .entries
        .iter()
        .find(|entry| entry.oracle_name == "final_exposure")
        .expect("final exposure oracle is recorded");
    assert!(!final_exposure.evidence.passed);
    assert_eq!(final_exposure.evidence.invariant, "final_exposure");

    let cancellation_drain = result
        .evidence_ledger
        .entries
        .iter()
        .find(|entry| entry.oracle_name == "cancellation_drain")
        .expect("cancellation drain oracle is recorded");
    assert!(!cancellation_drain.evidence.passed);
    assert_eq!(cancellation_drain.evidence.invariant, "cancellation_drain");
}

#[test]
fn test_atp_obligation_tracking_basic() -> Result<(), Box<dyn std::error::Error>> {
    let tracker = std::sync::Arc::new(AtpObligationTracker::new());

    // Test basic obligation lifecycle
    let obligation_id = tracker.create_obligation(
        ObligationType::Transfer("test_transfer".to_string()),
        "test_creator".to_string(),
        HashMap::new(),
    );

    assert_eq!(tracker.obligation_count(), 1);

    // Test active obligations
    let active = tracker.active_obligations();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].obligation_id, obligation_id);

    // Test fulfillment
    let fulfilled = tracker.fulfill_obligation(&obligation_id);
    assert!(fulfilled);
    assert_eq!(tracker.obligation_count(), 0);

    // Test region quiescence
    tracker.validate_region_quiescence()?;

    Ok(())
}

fn ledger_evidence(invariant: &str, passed: bool, log10_bf: f64) -> EvidenceEntry {
    EvidenceEntry {
        invariant: invariant.to_string(),
        passed,
        bayes_factor: BayesFactor {
            log10_bf,
            hypothesis: format!("{invariant} violation"),
            strength: EvidenceStrength::from_log10_bf(log10_bf),
        },
        log_likelihoods: LogLikelihoodContributions {
            structural: log10_bf / 2.0,
            detection: log10_bf / 2.0,
            total: log10_bf,
        },
        evidence_lines: vec![EvidenceLine {
            equation: "BF = P(data | violation) / P(data | clean)".to_string(),
            substitution: format!("log10_bf={log10_bf}"),
            intuition: format!("{invariant} deterministic evidence"),
        }],
    }
}

fn violation_result(oracle_name: &str) -> TransferOracleResult {
    TransferOracleResult {
        oracle_name: oracle_name.to_string(),
        violations: vec![transfer_violation(
            oracle_name,
            &format!("{oracle_name} failed"),
            ViolationSeverity::High,
        )],
        stats: OracleStats {
            entities_tracked: 1,
            events_recorded: 1,
        },
        passed: false,
    }
}

fn transfer_violation(
    violation_type: &str,
    description: &str,
    severity: ViolationSeverity,
) -> TransferViolation {
    TransferViolation {
        violation_type: violation_type.to_string(),
        description: description.to_string(),
        severity,
        evidence: BTreeMap::from([("source".to_string(), "test".to_string())]),
    }
}
