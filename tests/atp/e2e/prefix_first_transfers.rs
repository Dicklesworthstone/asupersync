//! E2E tests for ATP prefix-first delivery modes for media, models, and large files.
//!
//! Tests media/model prefix-first transfer, directory small-file-first transfer,
//! interrupted resume, consumer reads before completion, and failed verification scenarios
//! per ATP-E4 acceptance criteria.

use asupersync::atp::sdk::{AtpClient, DirectoryHandle, StreamHandle, TransferOptions};
use asupersync::atp::stream_object::ConsumptionPolicy;
use asupersync::atp::sync::{DirectoryEarlyUsabilityPolicy, DirectoryFinalCommitState};
use asupersync::error::Result;
use asupersync::types::Time;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

/// E2E test for media file prefix-first transfer
#[tokio::test]
async fn test_media_prefix_first_transfer() -> Result<()> {
    tracing_subscriber::fmt().with_test_writer().init();

    info!("Starting media prefix-first transfer E2E test");

    // Setup: Create a large media file (simulated MP4)
    let temp_dir = TempDir::new()?;
    let media_path = temp_dir.path().join("video.mp4");

    // Create 10MB simulated media file with MP4 header at start
    let mut media_content = Vec::new();
    media_content.extend_from_slice(b"ftypisom"); // MP4 header
    media_content.extend_from_slice(&[0u8; 100]); // Header metadata
    media_content.resize(10 * 1024 * 1024, 0xAA); // Fill rest with pattern

    fs::write(&media_path, &media_content).await?;

    // Initialize ATP client and create transfer
    let client = AtpClient::new().await?;
    let transfer_opts = TransferOptions {
        enable_prefix_delivery: true,
        consumption_policy: ConsumptionPolicy::VerifiedOnly,
        large_file_threshold: 1024 * 1024, // 1MB
        ..Default::default()
    };

    let stream_handle = client.send_file(&media_path, transfer_opts).await?;

    info!("Media transfer started, object_id: {}", stream_handle.object_id());

    // Test: Consumer starts reading while transfer is in progress
    let mut consumer_buffer = Vec::new();
    let mut total_read = 0;
    let start_time = std::time::Instant::now();

    while total_read < 1024 * 1024 { // Read first 1MB
        // Check verified prefix
        let verified_end = stream_handle.verified_prefix_end();
        if verified_end > total_read {
            let chunk_size = std::cmp::min(64 * 1024, verified_end - total_read); // 64KB chunks
            let mut chunk_buffer = vec![0u8; chunk_size];

            let bytes_read = stream_handle.read_verified_range(
                total_read,
                &mut chunk_buffer,
                ConsumptionPolicy::VerifiedOnly,
            ).await?;

            if bytes_read > 0 {
                consumer_buffer.extend_from_slice(&chunk_buffer[..bytes_read]);
                total_read += bytes_read;

                info!("Read {}KB verified prefix, total: {}KB, verified_end: {}KB",
                    bytes_read / 1024, total_read / 1024, verified_end / 1024);
            }
        }

        // Small delay to allow more chunks to be verified
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Timeout after 30 seconds
        if start_time.elapsed() > Duration::from_secs(30) {
            warn!("Timeout reached, stopping prefix consumption");
            break;
        }
    }

    // Verify: Consumer received valid MP4 header early
    assert!(consumer_buffer.len() >= 108, "Should have read at least header");
    assert_eq!(&consumer_buffer[0..8], b"ftypisom", "Should have valid MP4 header");

    // Verify: Prefix delivery provided usable content before full transfer
    assert!(total_read >= 512 * 1024, "Should have read at least 512KB prefix");
    assert!(total_read < media_content.len(), "Should not have read entire file yet");

    info!("Media prefix-first transfer test passed: read {}KB prefix with valid header",
        total_read / 1024);

    Ok(())
}

/// E2E test for model file prefix-first transfer (ML model format)
#[tokio::test]
async fn test_model_prefix_first_transfer() -> Result<()> {
    info!("Starting ML model prefix-first transfer E2E test");

    // Setup: Create simulated ML model file with metadata header
    let temp_dir = TempDir::new()?;
    let model_path = temp_dir.path().join("model.safetensors");

    let mut model_content = Vec::new();
    // Simulated safetensors header with metadata
    let metadata = r#"{"format":"safetensors","model_type":"transformer","layers":24}"#;
    let header_size = metadata.len() as u64;

    model_content.extend_from_slice(&header_size.to_le_bytes());
    model_content.extend_from_slice(metadata.as_bytes());
    model_content.resize(50 * 1024 * 1024, 0xBB); // 50MB model weights

    fs::write(&model_path, &model_content).await?;

    // Initialize transfer with model-specific options
    let client = AtpClient::new().await?;
    let transfer_opts = TransferOptions {
        enable_prefix_delivery: true,
        consumption_policy: ConsumptionPolicy::VerifiedOnly,
        large_file_threshold: 1024 * 1024,
        priority_first_bytes: 64 * 1024, // Prioritize first 64KB for metadata
        ..Default::default()
    };

    let stream_handle = client.send_file(&model_path, transfer_opts).await?;

    info!("Model transfer started, prioritizing metadata prefix");

    // Test: Read metadata before model weights arrive
    let mut metadata_buffer = Vec::new();
    let target_metadata_size = 8 + metadata.len(); // header_size + metadata
    let start_time = std::time::Instant::now();

    while metadata_buffer.len() < target_metadata_size {
        let verified_end = stream_handle.verified_prefix_end();
        if verified_end > metadata_buffer.len() {
            let read_size = std::cmp::min(
                target_metadata_size - metadata_buffer.len(),
                verified_end - metadata_buffer.len(),
            );
            let mut chunk = vec![0u8; read_size];

            let bytes_read = stream_handle.read_verified_range(
                metadata_buffer.len(),
                &mut chunk,
                ConsumptionPolicy::VerifiedOnly,
            ).await?;

            if bytes_read > 0 {
                metadata_buffer.extend_from_slice(&chunk[..bytes_read]);
                info!("Read metadata chunk: {} bytes, total metadata: {} bytes",
                    bytes_read, metadata_buffer.len());
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        if start_time.elapsed() > Duration::from_secs(30) {
            break;
        }
    }

    // Verify: Metadata is readable before full model transfer
    assert!(metadata_buffer.len() >= target_metadata_size, "Should have complete metadata");

    let header_size_bytes = &metadata_buffer[0..8];
    let actual_header_size = u64::from_le_bytes(header_size_bytes.try_into().unwrap());
    assert_eq!(actual_header_size, metadata.len() as u64, "Header size should match");

    let actual_metadata = std::str::from_utf8(&metadata_buffer[8..8 + metadata.len()])?;
    assert!(actual_metadata.contains("transformer"), "Should have model metadata");

    info!("Model prefix-first transfer test passed: metadata accessible before full transfer");

    Ok(())
}

/// E2E test for directory small-file-first transfer
#[tokio::test]
async fn test_directory_small_file_first_transfer() -> Result<()> {
    info!("Starting directory small-file-first transfer E2E test");

    // Setup: Create directory with mixed file sizes
    let temp_dir = TempDir::new()?;
    let source_dir = temp_dir.path().join("source");
    fs::create_dir(&source_dir).await?;

    // Create files of different sizes
    fs::write(source_dir.join("README.md"), "# Project Documentation\n\nQuick start guide...").await?;
    fs::write(source_dir.join("config.json"), r#"{"version": "1.0", "features": ["fast"]}"#).await?;
    fs::write(source_dir.join("small_script.py"), "print('hello world')").await?;

    // Large files that should be withheld initially
    fs::write(source_dir.join("large_data.bin"), vec![0xFF; 10 * 1024]).await?; // 10KB
    fs::write(source_dir.join("huge_asset.zip"), vec![0xCC; 100 * 1024]).await?; // 100KB

    // Initialize directory transfer
    let client = AtpClient::new().await?;
    let transfer_opts = TransferOptions {
        enable_prefix_delivery: true,
        consumption_policy: ConsumptionPolicy::VerifiedOnly,
        ..Default::default()
    };

    let dir_handle = client.send_directory(&source_dir, transfer_opts).await?;

    info!("Directory transfer started");

    // Test: Check early usability report for small files
    let policy = DirectoryEarlyUsabilityPolicy {
        expose_metadata_before_final: true,
        small_file_threshold_bytes: 1024, // 1KB threshold
        expose_small_files_early: true,
    };

    let start_time = std::time::Instant::now();
    let mut small_files_available = false;

    while !small_files_available && start_time.elapsed() < Duration::from_secs(30) {
        let report = dir_handle.early_usability_report(
            policy,
            "e2e-directory-small-files",
        );

        // Check if small files are exposed early
        let exposed_small_files: Vec<_> = report.entries.iter()
            .filter(|e| e.content_visible && e.estimated_size.unwrap_or(0) <= 1024)
            .collect();

        let withheld_large_files: Vec<_> = report.entries.iter()
            .filter(|e| !e.content_visible && e.estimated_size.unwrap_or(0) > 1024)
            .collect();

        info!("Early usability report: {} small files exposed, {} large files withheld",
            exposed_small_files.len(), withheld_large_files.len());

        if exposed_small_files.len() >= 3 { // README, config, script
            small_files_available = true;

            // Verify specific small files are exposed
            let readme_exposed = exposed_small_files.iter()
                .any(|e| e.path.to_string().contains("README.md"));
            let config_exposed = exposed_small_files.iter()
                .any(|e| e.path.to_string().contains("config.json"));

            assert!(readme_exposed, "README.md should be exposed early");
            assert!(config_exposed, "config.json should be exposed early");

            // Verify large files are properly withheld
            assert!(!withheld_large_files.is_empty(), "Large files should be withheld");

            info!("Small files correctly exposed while large files withheld");
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(small_files_available, "Small files should become available early");

    Ok(())
}

/// E2E test for interrupted resume scenario
#[tokio::test]
async fn test_interrupted_resume_scenario() -> Result<()> {
    info!("Starting interrupted resume E2E test");

    // Setup: Create large file for transfer
    let temp_dir = TempDir::new()?;
    let large_file = temp_dir.path().join("large_file.dat");
    let file_size = 5 * 1024 * 1024; // 5MB
    let pattern_data = (0..file_size).map(|i| (i % 256) as u8).collect::<Vec<_>>();

    fs::write(&large_file, &pattern_data).await?;

    // Phase 1: Start transfer and read some prefix
    let client = AtpClient::new().await?;
    let transfer_opts = TransferOptions {
        enable_prefix_delivery: true,
        consumption_policy: ConsumptionPolicy::VerifiedOnly,
        ..Default::default()
    };

    let stream_handle = client.send_file(&large_file, transfer_opts.clone()).await?;
    let object_id = stream_handle.object_id().to_string();

    // Read initial prefix
    let mut phase1_buffer = Vec::new();
    let target_phase1 = 1024 * 1024; // 1MB
    let start_time = std::time::Instant::now();

    while phase1_buffer.len() < target_phase1 && start_time.elapsed() < Duration::from_secs(10) {
        let verified_end = stream_handle.verified_prefix_end();
        if verified_end > phase1_buffer.len() {
            let read_size = std::cmp::min(64 * 1024, verified_end - phase1_buffer.len());
            let mut chunk = vec![0u8; read_size];

            let bytes_read = stream_handle.read_verified_range(
                phase1_buffer.len(),
                &mut chunk,
                ConsumptionPolicy::VerifiedOnly,
            ).await?;

            if bytes_read > 0 {
                phase1_buffer.extend_from_slice(&chunk[..bytes_read]);
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let phase1_read = phase1_buffer.len();
    info!("Phase 1: Read {} bytes before interruption", phase1_read);

    // Phase 2: Simulate interruption and resume
    drop(stream_handle); // Simulate connection loss

    let resumed_handle = client.resume_file(&object_id, transfer_opts).await?;

    info!("Transfer resumed from interruption");

    // Verify: Resume preserves prefix safety
    let resume_verified_end = resumed_handle.verified_prefix_end();
    assert!(resume_verified_end <= phase1_read,
        "Resume should not claim more verification than previously achieved");

    // Continue reading from safe resume point
    let mut phase2_buffer = Vec::new();
    let resume_start = resumed_handle.safe_resume_offset();

    while phase2_buffer.len() < 512 * 1024 { // Read additional 512KB
        let verified_end = resumed_handle.verified_prefix_end();
        let read_offset = resume_start + phase2_buffer.len();

        if verified_end > read_offset {
            let read_size = std::cmp::min(32 * 1024, verified_end - read_offset);
            let mut chunk = vec![0u8; read_size];

            let bytes_read = resumed_handle.read_verified_range(
                read_offset,
                &mut chunk,
                ConsumptionPolicy::VerifiedOnly,
            ).await?;

            if bytes_read > 0 {
                phase2_buffer.extend_from_slice(&chunk[..bytes_read]);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        if std::time::Instant::now().duration_since(start_time) > Duration::from_secs(30) {
            break;
        }
    }

    // Verify: Data integrity across resume
    let expected_phase2_start = resume_start;
    if !phase2_buffer.is_empty() {
        assert_eq!(
            phase2_buffer[0],
            (expected_phase2_start % 256) as u8,
            "Resume should maintain data integrity"
        );
    }

    info!("Interrupted resume test passed: {} bytes in phase 1, {} bytes in phase 2",
        phase1_read, phase2_buffer.len());

    Ok(())
}

/// E2E test for consumer reads before completion
#[tokio::test]
async fn test_consumer_reads_before_completion() -> Result<()> {
    info!("Starting consumer reads before completion E2E test");

    // Setup: Create streaming scenario
    let temp_dir = TempDir::new()?;
    let stream_file = temp_dir.path().join("stream.log");

    // Start with initial content
    fs::write(&stream_file, "Initial log entry\n").await?;

    let client = AtpClient::new().await?;
    let transfer_opts = TransferOptions {
        enable_prefix_delivery: true,
        consumption_policy: ConsumptionPolicy::VerifiedOnly,
        streaming_mode: true,
        ..Default::default()
    };

    let stream_handle = client.send_file(&stream_file, transfer_opts).await?;

    // Consumer starts reading immediately
    let mut consumer_log = Vec::new();
    let mut consumer_offset = 0;

    // Simulate ongoing writes to source file during transfer
    let file_path = stream_file.clone();
    let write_task = tokio::spawn(async move {
        for i in 1..=20 {
            let entry = format!("Log entry {} at {}\n", i, Time::now());
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .await
                .unwrap();
            file.write_all(entry.as_bytes()).await.unwrap();
            file.flush().await.unwrap();

            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    // Consumer reads verified content as it becomes available
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < Duration::from_secs(10) {
        let verified_end = stream_handle.verified_prefix_end();

        if verified_end > consumer_offset {
            let read_size = verified_end - consumer_offset;
            let mut buffer = vec![0u8; read_size];

            let bytes_read = stream_handle.read_verified_range(
                consumer_offset,
                &mut buffer,
                ConsumptionPolicy::VerifiedOnly,
            ).await?;

            if bytes_read > 0 {
                consumer_log.extend_from_slice(&buffer[..bytes_read]);
                consumer_offset += bytes_read;

                let log_content = String::from_utf8_lossy(&consumer_log);
                let line_count = log_content.lines().count();

                info!("Consumer read {} bytes, total {} lines so far",
                    bytes_read, line_count);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Wait for writer to complete
    write_task.await.map_err(|e| anyhow::anyhow!("Write task failed: {}", e))?;

    // Verify: Consumer received log entries as they were written and verified
    let final_log = String::from_utf8_lossy(&consumer_log);
    assert!(final_log.contains("Initial log entry"), "Should have initial content");
    assert!(final_log.lines().count() >= 5, "Should have received multiple log entries");

    info!("Consumer reads before completion test passed: received {} lines",
        final_log.lines().count());

    Ok(())
}

/// E2E test for failed verification with detailed logs
#[tokio::test]
async fn test_failed_verification_detailed_logs() -> Result<()> {
    info!("Starting failed verification E2E test");

    // Setup: Create scenario that will trigger verification failure
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("corrupted_file.dat");

    // Create file with known content
    let original_content = b"This is the original content that should verify correctly";
    fs::write(&test_file, original_content).await?;

    let client = AtpClient::new().await?;
    let transfer_opts = TransferOptions {
        enable_prefix_delivery: true,
        consumption_policy: ConsumptionPolicy::VerifiedOnly,
        enable_detailed_logging: true,
        ..Default::default()
    };

    let stream_handle = client.send_file(&test_file, transfer_opts).await?;

    // Read some initial verified content
    let mut verified_content = Vec::new();
    while verified_content.len() < 32 && stream_handle.verified_prefix_end() > verified_content.len() {
        let mut chunk = vec![0u8; 16];
        let bytes_read = stream_handle.read_verified_range(
            verified_content.len(),
            &mut chunk,
            ConsumptionPolicy::VerifiedOnly,
        ).await?;

        if bytes_read > 0 {
            verified_content.extend_from_slice(&chunk[..bytes_read]);
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Simulate corruption during transfer (for testing)
    let corruption_offset = 20;
    stream_handle.inject_test_corruption(corruption_offset, b"CORRUPT").await?;

    info!("Injected corruption at offset {} for testing", corruption_offset);

    // Verification should detect corruption and invalidate subsequent content
    let mut verification_failed = false;
    let start_time = std::time::Instant::now();

    while !verification_failed && start_time.elapsed() < Duration::from_secs(10) {
        // Check if verification failure has been detected
        if stream_handle.has_verification_failure() {
            verification_failed = true;

            let failure_details = stream_handle.get_verification_failure_details().await?;

            info!("Verification failure detected: {:?}", failure_details);

            // Verify detailed logging
            assert!(failure_details.failure_offset.is_some(), "Should have failure offset");
            assert!(!failure_details.invalidation_reason.is_empty(), "Should have invalidation reason");
            assert!(failure_details.replay_pointer.is_some(), "Should have replay pointer");

            // Verify that verified prefix is truncated to safe point
            let safe_prefix_end = stream_handle.verified_prefix_end();
            assert!(safe_prefix_end <= corruption_offset,
                "Verified prefix should be truncated before corruption point");

            // Consumer should not be able to read beyond safe point
            let unsafe_read_attempt = stream_handle.read_verified_range(
                safe_prefix_end,
                &mut [0u8; 10],
                ConsumptionPolicy::VerifiedOnly,
            ).await;

            assert!(unsafe_read_attempt.is_err() || unsafe_read_attempt.unwrap() == 0,
                "Should not allow reads beyond safe verification point");
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(verification_failed, "Verification failure should have been detected");

    info!("Failed verification test passed with proper safety truncation");

    Ok(())
}

/// Helper: Create ATP client for testing
impl AtpClient {
    async fn new() -> Result<Self> {
        // Initialize test ATP client
        todo!("Implement ATP client initialization")
    }

    async fn send_file(&self, _path: &Path, _opts: TransferOptions) -> Result<StreamHandle> {
        todo!("Implement file sending")
    }

    async fn send_directory(&self, _path: &Path, _opts: TransferOptions) -> Result<DirectoryHandle> {
        todo!("Implement directory sending")
    }

    async fn resume_file(&self, _object_id: &str, _opts: TransferOptions) -> Result<StreamHandle> {
        todo!("Implement file resume")
    }
}

/// Transfer options for E2E tests
#[derive(Default, Clone)]
struct TransferOptions {
    pub enable_prefix_delivery: bool,
    pub consumption_policy: ConsumptionPolicy,
    pub large_file_threshold: usize,
    pub priority_first_bytes: usize,
    pub streaming_mode: bool,
    pub enable_detailed_logging: bool,
}

/// Test-specific extensions for stream handles
impl StreamHandle {
    async fn read_verified_range(&self, _offset: usize, _buffer: &mut [u8], _policy: ConsumptionPolicy) -> Result<usize> {
        todo!("Implement verified range reading")
    }

    fn safe_resume_offset(&self) -> usize {
        todo!("Implement safe resume offset calculation")
    }

    async fn inject_test_corruption(&self, _offset: usize, _corrupt_data: &[u8]) -> Result<()> {
        todo!("Implement test corruption injection")
    }

    fn has_verification_failure(&self) -> bool {
        todo!("Implement verification failure check")
    }

    async fn get_verification_failure_details(&self) -> Result<VerificationFailureDetails> {
        todo!("Implement failure details retrieval")
    }
}

#[derive(Debug)]
struct VerificationFailureDetails {
    pub failure_offset: Option<usize>,
    pub invalidation_reason: String,
    pub replay_pointer: Option<String>,
}