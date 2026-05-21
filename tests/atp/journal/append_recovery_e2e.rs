//! Journal Append and Recovery E2E Tests

use super::*;
#[test]
fn test_journal_append_recovery_basic() -> Result<(), Box<dyn std::error::Error>> {
    let config = JournalTestConfig::default();
    let mut harness = JournalTestHarness::new(config.clone())?;

    harness.run_crash_matrix("journal_append_recovery", |config, crash_point| {
        let mut artifact = JournalTestArtifact::new("journal_append_recovery".to_string());

        if let Some(cp) = crash_point {
            artifact = artifact.with_crash_point(cp);
        }

        // Create test journal entries
        let entries = vec![
            test_utils::create_test_journal_entry(ObjectId::new(), ObjectKind::FileObject),
            test_utils::create_test_journal_entry(ObjectId::new(), ObjectKind::DirectoryObject),
            test_utils::create_test_journal_entry(ObjectId::new(), ObjectKind::StreamObject),
        ];

        // Simulate journal append operations
        for (i, entry) in entries.iter().enumerate() {
            artifact.record_journal_entry(entry.clone());

            // Simulate crash during append
            if crash_point == Some(JournalCrashPoint::JournalAppend) && i == 1 {
                artifact.record_recovery_state(RecoveryState::AppendFailed);
                return Err("Simulated crash during journal append".into());
            }

            // Record fsync after each append
            artifact.record_fsync();
        }

        // Test recovery from append log
        if crash_point == Some(JournalCrashPoint::Recovery) {
            artifact.record_recovery_state(RecoveryState::InProgress);
            // Verify journal consistency during recovery
            let checksum = test_utils::verify_journal_checksum(&config.journal_path)?;
            artifact.record_verification_hash("journal_checksum".to_string(), checksum);
        } else {
            artifact.record_recovery_state(RecoveryState::Completed);
        }

        artifact.journal_size = config.journal_path.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(artifact)
    })?;

    harness.verify_journal_integrity()?;
    harness.generate_lab_artifacts()?;

    Ok(())
}

#[test]
fn test_journal_concurrent_append() -> Result<(), Box<dyn std::error::Error>> {
    let config = JournalTestConfig::default();
    let mut harness = JournalTestHarness::new(config.clone())?;

    harness.run_crash_matrix("journal_concurrent_append", |config, crash_point| {
        let mut artifact = JournalTestArtifact::new("journal_concurrent_append".to_string());

        if let Some(cp) = crash_point {
            artifact = artifact.with_crash_point(cp);
        }

        // Simulate concurrent append operations
        for batch in 0..5 {
            for entry_in_batch in 0..10 {
                let entry =
                    test_utils::create_test_journal_entry(ObjectId::new(), ObjectKind::FileObject);
                artifact.record_journal_entry(entry);

                // Test crash during concurrent operations
                if crash_point == Some(JournalCrashPoint::JournalAppend)
                    && batch == 2
                    && entry_in_batch == 5
                {
                    artifact.record_recovery_state(RecoveryState::ConcurrentAppendFailed);
                    return Err("Simulated crash during concurrent append".into());
                }
            }

            // Batch fsync
            if batch % 2 == 0 {
                artifact.record_fsync();
            }
        }

        artifact.record_recovery_state(RecoveryState::Completed);
        Ok(artifact)
    })?;

    harness.verify_journal_integrity()?;
    harness.generate_lab_artifacts()?;

    Ok(())
}
