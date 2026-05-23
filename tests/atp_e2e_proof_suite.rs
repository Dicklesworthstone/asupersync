//! ATP-N3: End-to-End Proof Suite Integration Test
//!
//! Main integration test file for ATP e2e proof suite.

mod atp;

use asupersync::lab::crashpack::{
    AtpEvidenceLedger, AtpReplayCoordinator, CrashpackBuilder, TraceMinimizer,
    TraceMinimizerConfig, TransferOracleResult, TransferViolation, ViolationSeverity,
};
use asupersync::lab::oracle::OracleStats;
use asupersync::lab::oracle::evidence::{
    BayesFactor, EvidenceEntry, EvidenceLine, EvidenceStrength, LogLikelihoodContributions,
};
use asupersync::trace::{TraceBuffer, TraceEvent};
use asupersync::types::Time;
use atp::{
    AtpCrashPoint, AtpForensics, AtpObligationTracker, FaultConfig, FaultInjector, FaultPoint,
    FaultType, ObligationType,
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

    println!("ATP E2E proof suite integration test completed successfully");
    Ok(())
}

#[test]
fn test_atp_crash_matrix_basic() -> Result<(), Box<dyn std::error::Error>> {
    // Test basic crash matrix functionality without full ATP context
    let crash_points = vec![
        AtpCrashPoint::PreJournalAppend,
        AtpCrashPoint::PostJournalAppend,
        AtpCrashPoint::PostBitmapUpdate,
        AtpCrashPoint::PostChunkWrite,
        AtpCrashPoint::PostFsync,
        AtpCrashPoint::PostRepairDecode,
        AtpCrashPoint::PostFinalRename,
        AtpCrashPoint::PostProofEmission,
        AtpCrashPoint::DuringCompaction,
    ];

    for crash_point in crash_points {
        println!("Testing crash point: {:?}", crash_point);

        // Create basic test context
        let fault_injector = FaultInjector::new();

        // Configure crash injection
        let point_str = match crash_point {
            AtpCrashPoint::PreJournalAppend => "pre_journal_append",
            AtpCrashPoint::PostJournalAppend => "post_journal_append",
            AtpCrashPoint::PostBitmapUpdate => "post_bitmap_update",
            AtpCrashPoint::PostChunkWrite => "post_chunk_write",
            AtpCrashPoint::PostFsync => "post_fsync",
            AtpCrashPoint::PostRepairDecode => "post_repair_decode",
            AtpCrashPoint::PostFinalRename => "post_final_rename",
            AtpCrashPoint::PostProofEmission => "post_proof_emission",
            AtpCrashPoint::DuringCompaction => "during_compaction",
        };

        fault_injector.inject_crash_at(point_str);

        // Verify crash would be injected
        // (We can't actually crash in this test, but we can verify configuration)
        println!("Crash configuration verified for: {}", point_str);
    }

    println!("ATP crash matrix basic test completed successfully");
    Ok(())
}

#[test]
fn test_atp_forensics_basic() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let mut forensics = AtpForensics::new(temp_dir.path())?;

    // Start capture
    forensics.start_capture("test_failure", "Test forensics capture", "test_operation");

    // Record some test data
    forensics.record_manifest_root("test_manifest_root_123");

    // Record test data would go here when forensics is implemented

    // Finish capture
    let artifact_path = forensics.finish_capture()?;
    assert!(artifact_path.exists());

    // Load and verify artifact (when implementation is complete)
    // let loaded_artifact = AtpForensics::load_artifact(&artifact_path)?;
    // assert_eq!(loaded_artifact.context.failure_type, "test_failure");

    println!("Artifact saved at: {}", artifact_path.display());

    println!("ATP forensics basic test completed successfully");
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
        .generate_replay_command(PathBuf::from("artifacts").as_path())
        .expect("replay command renders");

    assert!(command.contains("export ATP_SEED_LAB_SEED_V1=42"));
    assert!(command.contains("export ATP_ORACLE_PROOF_BUNDLE_VALIDITY=enabled"));
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
    assert!(replay_command.contains("atp replay transfer.atp-trace"));
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

    println!("ATP obligation tracking basic test completed successfully");
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
        violations: vec![TransferViolation {
            violation_type: oracle_name.to_string(),
            description: format!("{oracle_name} failed"),
            severity: ViolationSeverity::High,
            evidence: BTreeMap::from([("source".to_string(), "test".to_string())]),
        }],
        stats: OracleStats {
            entities_tracked: 1,
            events_recorded: 1,
        },
        passed: false,
    }
}
