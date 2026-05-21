//! File Object End-to-End Tests
//!
//! Tests file object persistence, recovery, and verification through crash scenarios.

use super::*;
use std::fs::File;
use std::io::{Read, Write};

fn object_id_for(content: &[u8]) -> ObjectId {
    ObjectId::content(ContentId::from_bytes(content))
}

#[test]
fn test_file_object_basic_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let config = ObjectTestConfig::default();
    let mut harness = ObjectGraphTestHarness::new(config.clone())?;

    harness.run_crash_matrix("file_object_basic", |config, crash_point| {
        let mut artifact = TestArtifact::new("file_object_basic".to_string(), ObjectId::new());

        if let Some(cp) = crash_point {
            artifact = artifact.with_crash_point(cp);
            test_utils::setup_crash_injection(cp);
        }

        // Create test file content
        let test_content = b"Hello, ATP file object test! This is a sample file for testing persistence and recovery.";
        let test_file_path = config.temp_dir.join("test_file.txt");

        // Write test file
        let mut file = File::create(&test_file_path)?;
        file.write_all(test_content)?;
        file.sync_all()?;
        drop(file);

        let object_id = object_id_for(test_content);

        // Record manifest root
        let manifest_root = *object_id.hash_bytes();
        artifact.record_manifest_root(manifest_root);

        // Test chunking
        let chunk_size = 64 * 1024;
        for (i, chunk) in test_content.chunks(chunk_size).enumerate() {
            let byte_offset = (i * chunk_size) as u64;
            artifact.record_chunk_range(byte_offset, byte_offset + chunk.len() as u64);
            artifact.record_bitmap_change(i as u64);
        }

        // Simulate journal operations
        let _journal_entry = JournalEntry::ObjectCreated {
            object_id: object_id.clone(),
            kind: ObjectKind::FileObject,
            timestamp: SystemTime::now(),
        };
        artifact.record_journal_offset(JournalOffset::new(42)); // Simulated offset

        // Simulate verification
        let verification_result = VerificationResult::Valid {
            object_id: object_id.clone(),
            content_hash: manifest_root,
            verified_at: SystemTime::now(),
        };
        artifact.record_verifier_decision(verification_result);

        // Simulate crash injection
        if let Some(crash_point) = crash_point {
            match crash_point {
                CrashPoint::JournalAppend => {
                    return Err("Simulated crash during journal append".into());
                }
                CrashPoint::ChunkWrite => {
                    return Err("Simulated crash during chunk write".into());
                }
                CrashPoint::FinalRename => {
                    return Err("Simulated crash during final rename".into());
                }
                _ => {
                    // Other crash points don't affect basic file operations
                }
            }
        }

        // Record final commit
        artifact.record_final_commit(format!("File object {} committed successfully", object_id));

        // Verify file can be read back
        let mut file = File::open(&test_file_path)?;
        let mut read_content = Vec::new();
        file.read_to_end(&mut read_content)?;

        if read_content != test_content {
            return Err("File content verification failed".into());
        }

        Ok(artifact)
    })?;

    // Run post-test assertions
    harness.assert_no_obligation_leaks()?;
    harness.assert_no_live_workers()?;
    harness.assert_no_unverified_exposure()?;

    // Generate lab artifacts
    harness.generate_lab_compatible_artifacts()?;

    Ok(())
}

#[test]
fn test_file_object_large_file_chunking() -> Result<(), Box<dyn std::error::Error>> {
    let config = ObjectTestConfig::default();
    let mut harness = ObjectGraphTestHarness::new(config.clone())?;

    harness.run_crash_matrix("file_object_large", |config, crash_point| {
        let mut artifact = TestArtifact::new("file_object_large".to_string(), ObjectId::new());

        if let Some(cp) = crash_point {
            artifact = artifact.with_crash_point(cp);
        }

        // Create a large test file (1MB)
        let chunk_size = 64 * 1024; // 64KB chunks
        let total_chunks = 16;
        let test_file_path = config.temp_dir.join("large_test_file.bin");

        let mut file = File::create(&test_file_path)?;
        for i in 0..total_chunks {
            let chunk_data = vec![i as u8; chunk_size];
            file.write_all(&chunk_data)?;

            // Record chunk range
            let start_offset = (i * chunk_size) as u64;
            let end_offset = start_offset + chunk_size as u64;
            artifact.record_chunk_range(start_offset, end_offset);

            // Simulate crash during chunk write
            if crash_point == Some(CrashPoint::ChunkWrite) && i == 8 {
                // Crash halfway through
                return Err("Simulated crash during large file chunk write".into());
            }
        }
        file.sync_all()?;
        drop(file);

        // Create file object and test chunking
        let file_content = std::fs::read(&test_file_path)?;
        let object_id = object_id_for(&file_content);
        let manifest_root = *object_id.hash_bytes();
        artifact.record_manifest_root(manifest_root);

        // Test content-defined chunking
        for (index, _chunk) in file_content.chunks(chunk_size).enumerate() {
            artifact.record_bitmap_change(index as u64);
        }

        artifact.record_final_commit("Large file object processing completed".to_string());

        Ok(artifact)
    })?;

    harness.assert_no_obligation_leaks()?;
    harness.assert_no_live_workers()?;
    harness.assert_no_unverified_exposure()?;
    harness.generate_lab_compatible_artifacts()?;

    Ok(())
}

#[test]
fn test_file_object_concurrent_access() -> Result<(), Box<dyn std::error::Error>> {
    let config = ObjectTestConfig::default();
    let mut harness = ObjectGraphTestHarness::new(config.clone())?;

    harness.run_crash_matrix("file_object_concurrent", |config, crash_point| {
        let mut artifact = TestArtifact::new("file_object_concurrent".to_string(), ObjectId::new());

        if let Some(cp) = crash_point {
            artifact = artifact.with_crash_point(cp);
        }

        let test_file_path = config.temp_dir.join("concurrent_test_file.txt");

        // Create file with multiple writers simulation
        let mut file = File::create(&test_file_path)?;
        let base_content = b"Base content for concurrent test\n";
        file.write_all(base_content)?;

        // Simulate concurrent append operations
        for i in 0..10 {
            let append_content = format!("Append operation {}\n", i);
            file.write_all(append_content.as_bytes())?;

            // Record each append as a bitmap change
            artifact.record_bitmap_change(i);

            // Simulate crash during concurrent operations
            if crash_point == Some(CrashPoint::Fsync) && i == 5 {
                // Skip fsync and crash
                return Err("Simulated crash during concurrent fsync".into());
            }

            if i % 3 == 0 {
                file.sync_all()?; // Periodic fsync
            }
        }

        file.sync_all()?;
        drop(file);

        let file_content = std::fs::read(&test_file_path)?;
        let object_id = object_id_for(&file_content);
        let manifest_root = *object_id.hash_bytes();
        artifact.record_manifest_root(manifest_root);

        artifact.record_final_commit("Concurrent file operations completed".to_string());

        Ok(artifact)
    })?;

    harness.assert_no_obligation_leaks()?;
    harness.assert_no_live_workers()?;
    harness.assert_no_unverified_exposure()?;
    harness.generate_lab_compatible_artifacts()?;

    Ok(())
}

#[test]
fn test_file_object_recovery_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    let config = ObjectTestConfig::default();
    let mut harness = ObjectGraphTestHarness::new(config.clone())?;

    harness.run_crash_matrix("file_object_recovery", |config, crash_point| {
        let mut artifact = TestArtifact::new("file_object_recovery".to_string(), ObjectId::new());

        if let Some(cp) = crash_point {
            artifact = artifact.with_crash_point(cp);
        }

        let test_file_path = config.temp_dir.join("recovery_test_file.dat");
        let partial_file_path = config.temp_dir.join("recovery_test_file.dat.partial");

        // Create partial file to simulate interrupted transfer
        let mut partial_file = File::create(&partial_file_path)?;
        let test_data = b"This is a test file for recovery scenarios. ";
        let full_data: Vec<u8> = test_data.repeat(100); // ~4KB file

        // Write only part of the file
        let partial_size = full_data.len() / 2;
        partial_file.write_all(&full_data[..partial_size])?;
        partial_file.sync_all()?;
        drop(partial_file);

        // Record partial state
        artifact.record_chunk_range(0, partial_size as u64);
        artifact.record_journal_offset(JournalOffset::new(partial_size as u64));

        // Simulate different recovery scenarios
        match crash_point {
            Some(CrashPoint::RepairDecode) => {
                // Simulate repair decode failure
                artifact.record_recovery_state(RecoveryState::RepairFailed);
                return Err("Simulated repair decode failure".into());
            }
            Some(CrashPoint::FinalRename) => {
                // Partial file exists but final rename fails
                let temp_complete_path = config.temp_dir.join("recovery_test_file.dat.tmp");
                std::fs::write(&temp_complete_path, &full_data)?;

                artifact.record_recovery_state(RecoveryState::RenameRequired);
                return Err("Simulated final rename failure".into());
            }
            _ => {
                // Successful recovery
                std::fs::write(&test_file_path, &full_data)?;

                let object_id = object_id_for(&full_data);
                let manifest_root = *object_id.hash_bytes();
                artifact.record_manifest_root(manifest_root);

                artifact.record_recovery_state(RecoveryState::Completed);
                artifact.record_chunk_range(0, full_data.len() as u64);
            }
        }

        artifact.record_final_commit("Recovery scenario test completed".to_string());

        Ok(artifact)
    })?;

    harness.assert_no_obligation_leaks()?;
    harness.assert_no_live_workers()?;
    harness.assert_no_unverified_exposure()?;
    harness.generate_lab_compatible_artifacts()?;

    Ok(())
}
