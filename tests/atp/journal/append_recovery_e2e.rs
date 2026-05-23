//! Journal Append and Recovery E2E Tests

use super::*;

fn config_for_journal_test(
    test_name: &str,
    crash_points: Vec<JournalCrashPoint>,
) -> JournalTestConfig {
    let temp_dir = std::env::temp_dir().join(format!(
        "atp_journal_tests_{test_name}_{}",
        std::process::id()
    ));

    JournalTestConfig {
        journal_path: temp_dir.join("journal.log"),
        bitmap_path: temp_dir.join("bitmap.dat"),
        temp_dir,
        crash_points,
        ..JournalTestConfig::default()
    }
}

#[test]
fn test_journal_append_recovery_basic() -> Result<(), Box<dyn std::error::Error>> {
    let config = config_for_journal_test(
        "append_recovery_basic",
        vec![
            JournalCrashPoint::JournalAppend,
            JournalCrashPoint::JournalFsync,
            JournalCrashPoint::Recovery,
        ],
    );
    let mut harness = JournalTestHarness::new(config.clone())?;

    harness.run_crash_matrix("journal_append_recovery", |config, crash_point| {
        test_utils::reset_test_files(config)?;

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
            if i == 1 {
                test_utils::inject_if_active(JournalCrashPoint::JournalAppend)?;
            }

            test_utils::persist_journal_entry(config, i as u64, entry)?;
            artifact.record_journal_entry(entry.clone());

            // Record fsync after each append
            if i == 1 {
                test_utils::inject_if_active(JournalCrashPoint::JournalFsync)?;
            }
            test_utils::fsync_journal(config)?;
            artifact.record_fsync();
        }

        // Test recovery from append log
        test_utils::inject_if_active(JournalCrashPoint::Recovery)?;

        let checksum = test_utils::verify_journal_checksum(&config.journal_path)?;
        artifact.record_verification_hash("journal_checksum".to_string(), checksum);
        artifact.record_recovery_state(RecoveryState::Completed);

        artifact.journal_size = config.journal_path.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(artifact)
    })?;

    harness.verify_journal_integrity()?;
    harness.generate_lab_artifacts()?;

    Ok(())
}

#[test]
fn test_journal_concurrent_append() -> Result<(), Box<dyn std::error::Error>> {
    let config = config_for_journal_test(
        "concurrent_append",
        vec![
            JournalCrashPoint::JournalAppend,
            JournalCrashPoint::JournalFsync,
        ],
    );
    let mut harness = JournalTestHarness::new(config.clone())?;

    harness.run_crash_matrix("journal_concurrent_append", |config, crash_point| {
        test_utils::reset_test_files(config)?;

        let mut artifact = JournalTestArtifact::new("journal_concurrent_append".to_string());

        if let Some(cp) = crash_point {
            artifact = artifact.with_crash_point(cp);
        }

        // Simulate concurrent append operations
        for batch in 0..5 {
            for entry_in_batch in 0..10 {
                let sequence = batch * 10 + entry_in_batch;
                if batch == 2 && entry_in_batch == 5 {
                    test_utils::inject_if_active(JournalCrashPoint::JournalAppend)?;
                }

                let entry =
                    test_utils::create_test_journal_entry(ObjectId::new(), ObjectKind::FileObject);
                test_utils::persist_journal_entry(config, sequence, &entry)?;
                artifact.record_journal_entry(entry);
            }

            // Batch fsync
            if batch % 2 == 0 {
                if batch == 2 {
                    test_utils::inject_if_active(JournalCrashPoint::JournalFsync)?;
                }
                test_utils::fsync_journal(config)?;
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
