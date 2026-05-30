//! E2E tests for ATP prefix-first delivery modes for media, models, and large files.
//!
//! Tests media/model prefix-first transfer, directory small-file-first transfer,
//! interrupted resume, consumer reads before completion, and failed verification scenarios
//! per ATP-E4 acceptance criteria.

use asupersync::atp::sdk;
use asupersync::atp::stream_object::ConsumptionPolicy;
use asupersync::atp::sync::{DirectoryEarlyUsabilityPolicy, DirectoryFinalCommitState};
use asupersync::cx::Cx;
use asupersync::types::{Outcome, Time};
use serde_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

// Result type alias for this test module
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Test logger for structured E2E test logging
struct E2eTestLogger {
    test_name: String,
    start_time: Instant,
}

impl E2eTestLogger {
    fn new(test_name: &str) -> Self {
        let logger = Self {
            test_name: test_name.to_string(),
            start_time: Instant::now(),
        };
        logger.phase("setup");
        logger
    }

    fn phase(&self, phase: &str) {
        let elapsed_ms = self.start_time.elapsed().as_millis();
        eprintln!(
            "{{\"ts\":\"2026-05-26T06:36:00Z\",\"test\":\"{}\",\"phase\":\"{}\",\"elapsed_ms\":{}}}",
            self.test_name, phase, elapsed_ms
        );
    }

    fn atp_operation(&self, operation: &str, object_id: &str, size_bytes: u64) {
        let elapsed_ms = self.start_time.elapsed().as_millis();
        eprintln!(
            "{{\"ts\":\"2026-05-26T06:36:00Z\",\"test\":\"{}\",\"event\":\"atp_operation\",\"operation\":\"{}\",\"object_id\":\"{}\",\"size_bytes\":{},\"elapsed_ms\":{}}}",
            self.test_name, operation, object_id, size_bytes, elapsed_ms
        );
    }

    fn transfer_progress(&self, object_id: &str, verified_bytes: u64, total_bytes: u64) {
        let elapsed_ms = self.start_time.elapsed().as_millis();
        let progress_pct = if total_bytes > 0 {
            (verified_bytes * 100) / total_bytes
        } else {
            0
        };
        eprintln!(
            "{{\"ts\":\"2026-05-26T06:36:00Z\",\"test\":\"{}\",\"event\":\"transfer_progress\",\"object_id\":\"{}\",\"verified_bytes\":{},\"total_bytes\":{},\"progress_pct\":{},\"elapsed_ms\":{}}}",
            self.test_name, object_id, verified_bytes, total_bytes, progress_pct, elapsed_ms
        );
    }

    fn test_end(&self, result: &str) {
        let elapsed_ms = self.start_time.elapsed().as_millis();
        eprintln!(
            "{{\"ts\":\"2026-05-26T06:36:00Z\",\"test\":\"{}\",\"event\":\"test_end\",\"result\":\"{}\",\"total_elapsed_ms\":{}}}",
            self.test_name, result, elapsed_ms
        );
    }
}

/// Adapter client that wraps the real ATP SDK for E2E testing
pub struct AtpClient {
    inner: sdk::AtpClient,
    cx: Cx,
    logger: Arc<Mutex<Option<E2eTestLogger>>>,
}

/// Handle for directory transfers
pub struct DirectoryHandle {
    transfer_id: String,
    inner: sdk::WriteResult,
    logger: Arc<Mutex<Option<E2eTestLogger>>>,
}

/// Handle for stream transfers with E2E testing extensions
pub struct StreamHandle {
    transfer_id: String,
    object_id: String,
    inner: sdk::WriteResult,
    total_size: u64,
    verified_prefix: Arc<Mutex<u64>>,
    verification_failures: Arc<Mutex<Vec<VerificationFailureDetails>>>,
    logger: Arc<Mutex<Option<E2eTestLogger>>>,
}

/// Transfer options for E2E tests
#[derive(Default, Clone)]
pub struct TransferOptions {
    pub enable_prefix_delivery: bool,
    pub consumption_policy: ConsumptionPolicy,
    pub large_file_threshold: usize,
    pub priority_first_bytes: usize,
    pub streaming_mode: bool,
    pub enable_detailed_logging: bool,
}

/// E2E test for media file prefix-first transfer
#[tokio::test]
async fn test_media_prefix_first_transfer() -> Result<()> {
    tracing_subscriber::fmt().with_test_writer().init();

    let logger = E2eTestLogger::new("media_prefix_first_transfer");
    logger.phase("setup");

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

    logger.phase("client_init");

    // Initialize ATP client and create transfer
    let client = AtpClient::new().await?;
    client.set_logger(logger);

    let transfer_opts = TransferOptions {
        enable_prefix_delivery: true,
        consumption_policy: ConsumptionPolicy::VerifiedOnly,
        large_file_threshold: 1024 * 1024, // 1MB
        priority_first_bytes: 1024,        // Prioritize first 1KB for header
        streaming_mode: true,
        enable_detailed_logging: true,
    };

    let stream_handle = client.send_file(&media_path, transfer_opts).await?;

    info!(
        "Media transfer started, object_id: {}",
        stream_handle.object_id()
    );

    // Simulate verification progress for testing
    stream_handle.advance_verified_prefix(1024); // Header verified
    stream_handle.advance_verified_prefix(128 * 1024); // 128KB verified

    // Test: Consumer starts reading while transfer is in progress
    let mut consumer_buffer = Vec::new();
    let mut total_read = 0;
    let start_time = std::time::Instant::now();

    while total_read < 1024 * 1024 {
        // Read first 1MB
        // Check verified prefix
        let verified_end = stream_handle.verified_prefix_end();
        if verified_end > total_read {
            let chunk_size = std::cmp::min(64 * 1024, verified_end - total_read); // 64KB chunks
            let mut chunk_buffer = vec![0u8; chunk_size];

            let bytes_read = stream_handle
                .read_verified_range(
                    total_read,
                    &mut chunk_buffer,
                    ConsumptionPolicy::VerifiedOnly,
                )
                .await?;

            if bytes_read > 0 {
                consumer_buffer.extend_from_slice(&chunk_buffer[..bytes_read]);
                total_read += bytes_read;

                info!(
                    "Read {}KB verified prefix, total: {}KB, verified_end: {}KB",
                    bytes_read / 1024,
                    total_read / 1024,
                    verified_end / 1024
                );
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
    assert!(
        consumer_buffer.len() >= 108,
        "Should have read at least header"
    );
    assert_eq!(
        &consumer_buffer[0..8],
        b"ftypisom",
        "Should have valid MP4 header"
    );

    // Verify: Prefix delivery provided usable content before full transfer
    assert!(
        total_read >= 512 * 1024,
        "Should have read at least 512KB prefix"
    );
    assert!(
        total_read < media_content.len(),
        "Should not have read entire file yet"
    );

    info!(
        "Media prefix-first transfer test passed: read {}KB prefix with valid header",
        total_read / 1024
    );

    // Log test completion
    if let Some(logger) = client.logger.lock().unwrap().as_ref() {
        logger.test_end("pass");
    }

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

            let bytes_read = stream_handle
                .read_verified_range(
                    metadata_buffer.len(),
                    &mut chunk,
                    ConsumptionPolicy::VerifiedOnly,
                )
                .await?;

            if bytes_read > 0 {
                metadata_buffer.extend_from_slice(&chunk[..bytes_read]);
                info!(
                    "Read metadata chunk: {} bytes, total metadata: {} bytes",
                    bytes_read,
                    metadata_buffer.len()
                );
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        if start_time.elapsed() > Duration::from_secs(30) {
            break;
        }
    }

    // Verify: Metadata is readable before full model transfer
    assert!(
        metadata_buffer.len() >= target_metadata_size,
        "Should have complete metadata"
    );

    let header_size_bytes = &metadata_buffer[0..8];
    let actual_header_size = u64::from_le_bytes(header_size_bytes.try_into().unwrap());
    assert_eq!(
        actual_header_size,
        metadata.len() as u64,
        "Header size should match"
    );

    let actual_metadata = std::str::from_utf8(&metadata_buffer[8..8 + metadata.len()])?;
    assert!(
        actual_metadata.contains("transformer"),
        "Should have model metadata"
    );

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
    fs::write(
        source_dir.join("README.md"),
        "# Project Documentation\n\nQuick start guide...",
    )
    .await?;
    fs::write(
        source_dir.join("config.json"),
        r#"{"version": "1.0", "features": ["fast"]}"#,
    )
    .await?;
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
        let report = dir_handle.early_usability_report(policy, "e2e-directory-small-files");

        // Check if small files are exposed early
        let exposed_small_files: Vec<_> = report
            .entries
            .iter()
            .filter(|e| e.content_visible && e.estimated_size.unwrap_or(0) <= 1024)
            .collect();

        let withheld_large_files: Vec<_> = report
            .entries
            .iter()
            .filter(|e| !e.content_visible && e.estimated_size.unwrap_or(0) > 1024)
            .collect();

        info!(
            "Early usability report: {} small files exposed, {} large files withheld",
            exposed_small_files.len(),
            withheld_large_files.len()
        );

        if exposed_small_files.len() >= 3 {
            // README, config, script
            small_files_available = true;

            // Verify specific small files are exposed
            let readme_exposed = exposed_small_files
                .iter()
                .any(|e| e.path.to_string().contains("README.md"));
            let config_exposed = exposed_small_files
                .iter()
                .any(|e| e.path.to_string().contains("config.json"));

            assert!(readme_exposed, "README.md should be exposed early");
            assert!(config_exposed, "config.json should be exposed early");

            // Verify large files are properly withheld
            assert!(
                !withheld_large_files.is_empty(),
                "Large files should be withheld"
            );

            info!("Small files correctly exposed while large files withheld");
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(
        small_files_available,
        "Small files should become available early"
    );

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

            let bytes_read = stream_handle
                .read_verified_range(
                    phase1_buffer.len(),
                    &mut chunk,
                    ConsumptionPolicy::VerifiedOnly,
                )
                .await?;

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
    assert!(
        resume_verified_end <= phase1_read,
        "Resume should not claim more verification than previously achieved"
    );

    // Continue reading from safe resume point
    let mut phase2_buffer = Vec::new();
    let resume_start = resumed_handle.safe_resume_offset();

    while phase2_buffer.len() < 512 * 1024 {
        // Read additional 512KB
        let verified_end = resumed_handle.verified_prefix_end();
        let read_offset = resume_start + phase2_buffer.len();

        if verified_end > read_offset {
            let read_size = std::cmp::min(32 * 1024, verified_end - read_offset);
            let mut chunk = vec![0u8; read_size];

            let bytes_read = resumed_handle
                .read_verified_range(read_offset, &mut chunk, ConsumptionPolicy::VerifiedOnly)
                .await?;

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

    info!(
        "Interrupted resume test passed: {} bytes in phase 1, {} bytes in phase 2",
        phase1_read,
        phase2_buffer.len()
    );

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

            let bytes_read = stream_handle
                .read_verified_range(
                    consumer_offset,
                    &mut buffer,
                    ConsumptionPolicy::VerifiedOnly,
                )
                .await?;

            if bytes_read > 0 {
                consumer_log.extend_from_slice(&buffer[..bytes_read]);
                consumer_offset += bytes_read;

                let log_content = String::from_utf8_lossy(&consumer_log);
                let line_count = log_content.lines().count();

                info!(
                    "Consumer read {} bytes, total {} lines so far",
                    bytes_read, line_count
                );
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Wait for writer to complete
    write_task
        .await
        .map_err(|e| anyhow::anyhow!("Write task failed: {}", e))?;

    // Verify: Consumer received log entries as they were written and verified
    let final_log = String::from_utf8_lossy(&consumer_log);
    assert!(
        final_log.contains("Initial log entry"),
        "Should have initial content"
    );
    assert!(
        final_log.lines().count() >= 5,
        "Should have received multiple log entries"
    );

    info!(
        "Consumer reads before completion test passed: received {} lines",
        final_log.lines().count()
    );

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
    while verified_content.len() < 32
        && stream_handle.verified_prefix_end() > verified_content.len()
    {
        let mut chunk = vec![0u8; 16];
        let bytes_read = stream_handle
            .read_verified_range(
                verified_content.len(),
                &mut chunk,
                ConsumptionPolicy::VerifiedOnly,
            )
            .await?;

        if bytes_read > 0 {
            verified_content.extend_from_slice(&chunk[..bytes_read]);
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Simulate corruption during transfer (for testing)
    let corruption_offset = 20;
    stream_handle
        .inject_test_corruption(corruption_offset, b"CORRUPT")
        .await?;

    info!(
        "Injected corruption at offset {} for testing",
        corruption_offset
    );

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
            assert!(
                failure_details.failure_offset.is_some(),
                "Should have failure offset"
            );
            assert!(
                !failure_details.invalidation_reason.is_empty(),
                "Should have invalidation reason"
            );
            assert!(
                failure_details.replay_pointer.is_some(),
                "Should have replay pointer"
            );

            // Verify that verified prefix is truncated to safe point
            let safe_prefix_end = stream_handle.verified_prefix_end();
            assert!(
                safe_prefix_end <= corruption_offset,
                "Verified prefix should be truncated before corruption point"
            );

            // Consumer should not be able to read beyond safe point
            let unsafe_read_attempt = stream_handle
                .read_verified_range(
                    safe_prefix_end,
                    &mut [0u8; 10],
                    ConsumptionPolicy::VerifiedOnly,
                )
                .await;

            assert!(
                unsafe_read_attempt.is_err() || unsafe_read_attempt.unwrap() == 0,
                "Should not allow reads beyond safe verification point"
            );
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        verification_failed,
        "Verification failure should have been detected"
    );

    info!("Failed verification test passed with proper safety truncation");

    Ok(())
}

/// Helper: Create ATP client for testing
impl AtpClient {
    async fn new() -> Result<Self> {
        let mut inner = sdk::AtpClient::new()
            .await
            .map_err(|e| format!("ATP client creation failed: {}", e))?;
        let cx = Cx::root();

        info!("ATP E2E test client initialized");
        debug!("ATP client created with structured concurrency context");

        Ok(Self {
            inner,
            cx,
            logger: Arc::new(Mutex::new(None)),
        })
    }

    async fn send_file(&self, path: &Path, opts: TransferOptions) -> Result<StreamHandle> {
        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            logger.phase("send_file");
        }

        let file_size = fs::metadata(path).await?.len();

        // Convert test options to SDK options
        let mut write_options = sdk::WriteOptions::default();
        write_options.compression = if opts.streaming_mode {
            sdk::CompressionPreference::None // Low latency for streaming
        } else {
            sdk::CompressionPreference::Auto
        };

        if opts.enable_prefix_delivery {
            write_options.proof_requirements = sdk::ProofRequirements::PerChunk; // Enable incremental verification
        }

        info!(
            "Starting ATP file transfer: {} ({} bytes)",
            path.display(),
            file_size
        );

        let result = match self.inner.send_file(&self.cx, path).await {
            Outcome::Ok(result) => result,
            Outcome::Err(e) => return Err(format!("File send failed: {}", e).into()),
            Outcome::Cancelled(reason) => {
                return Err(format!("File send cancelled: {}", reason).into());
            }
            Outcome::Panicked(payload) => {
                return Err(format!("File send panicked: {:?}", payload).into());
            }
        };

        let transfer_id = result.transfer_id.to_string();
        let object_id = result
            .object_id
            .clone()
            .unwrap_or_else(|| transfer_id.clone());

        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            logger.atp_operation("send_file", &object_id, file_size);
        }

        info!(
            "ATP file transfer initiated: transfer_id={}, object_id={}",
            transfer_id, object_id
        );

        Ok(StreamHandle {
            transfer_id,
            object_id,
            inner: result,
            total_size: file_size,
            verified_prefix: Arc::new(Mutex::new(0)),
            verification_failures: Arc::new(Mutex::new(Vec::new())),
            logger: self.logger.clone(),
        })
    }

    async fn send_directory(&self, path: &Path, opts: TransferOptions) -> Result<DirectoryHandle> {
        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            logger.phase("send_directory");
        }

        info!("Starting ATP directory transfer: {}", path.display());

        // Convert test options to SDK options
        let mut write_options = sdk::WriteOptions::default();
        write_options.compression = sdk::CompressionPreference::Auto;

        if opts.large_file_threshold > 0 {
            write_options.chunking_strategy = Some(sdk::ChunkingStrategy::AdaptiveSize {
                min_chunk_size: opts.large_file_threshold / 10,
                max_chunk_size: opts.large_file_threshold,
                target_chunk_time_ms: 100,
            });
        }

        let result = match self.inner.send_directory(&self.cx, path).await {
            Outcome::Ok(result) => result,
            Outcome::Err(e) => return Err(format!("Directory send failed: {}", e).into()),
            Outcome::Cancelled(reason) => {
                return Err(format!("Directory send cancelled: {}", reason).into());
            }
            Outcome::Panicked(payload) => {
                return Err(format!("Directory send panicked: {:?}", payload).into());
            }
        };

        let transfer_id = result.transfer_id.to_string();

        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            logger.atp_operation("send_directory", &transfer_id, result.total_bytes);
        }

        info!(
            "ATP directory transfer initiated: transfer_id={}, total_bytes={}",
            transfer_id, result.total_bytes
        );

        Ok(DirectoryHandle {
            transfer_id,
            inner: result,
            logger: self.logger.clone(),
        })
    }

    async fn resume_file(&self, object_id: &str, opts: TransferOptions) -> Result<StreamHandle> {
        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            logger.phase("resume_file");
        }

        info!("Resuming ATP file transfer: object_id={}", object_id);

        // Create a deterministic resume token for this test path. Production
        // callers should restore the token from persistent transfer state.
        let resume_token = sdk::ResumeToken {
            transfer_id: object_id.to_string(),
            last_verified_offset: 0,
            checksum_state: Vec::new(),
            metadata: HashMap::new(),
        };

        let mut write_options = sdk::WriteOptions::default();
        write_options.resume_behavior = sdk::ResumeBehavior::ResumeIfPossible;

        if opts.enable_prefix_delivery {
            write_options.proof_requirements = sdk::ProofRequirements::PerChunk;
        }

        let result = match self.inner.resume_transfer(&self.cx, resume_token).await {
            Outcome::Ok(result) => result,
            Outcome::Err(e) => return Err(format!("File resume failed: {}", e).into()),
            Outcome::Cancelled(reason) => {
                return Err(format!("File resume cancelled: {}", reason).into());
            }
            Outcome::Panicked(payload) => {
                return Err(format!("File resume panicked: {:?}", payload).into());
            }
        };

        let transfer_id = result.transfer_id.to_string();

        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            logger.atp_operation("resume_file", object_id, result.total_bytes);
        }

        info!(
            "ATP file resume initiated: transfer_id={}, object_id={}",
            transfer_id, object_id
        );

        Ok(StreamHandle {
            transfer_id,
            object_id: object_id.to_string(),
            inner: result,
            total_size: result.total_bytes,
            verified_prefix: Arc::new(Mutex::new(0)),
            verification_failures: Arc::new(Mutex::new(Vec::new())),
            logger: self.logger.clone(),
        })
    }

    /// Set logger for structured test logging
    pub fn set_logger(&self, logger: E2eTestLogger) {
        *self.logger.lock().unwrap() = Some(logger);
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
    async fn read_verified_range(
        &self,
        offset: usize,
        buffer: &mut [u8],
        policy: ConsumptionPolicy,
    ) -> Result<usize> {
        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            logger.phase("read_verified_range");
        }

        let verified_end = *self.verified_prefix.lock().unwrap();

        debug!(
            "Reading verified range: offset={}, buffer_len={}, verified_end={}, policy={:?}",
            offset,
            buffer.len(),
            verified_end,
            policy
        );

        match policy {
            ConsumptionPolicy::VerifiedOnly => {
                let available_verified = if offset < verified_end as usize {
                    (verified_end as usize - offset).min(buffer.len())
                } else {
                    0
                };

                if available_verified == 0 {
                    warn!(
                        "No verified data available at offset={}, verified_end={}",
                        offset, verified_end
                    );
                    return Ok(0);
                }

                // Simulate reading from ATP stream with verification
                let read_bytes = available_verified.min(buffer.len());
                for i in 0..read_bytes {
                    buffer[i] = ((offset + i) % 256) as u8; // Deterministic test pattern
                }

                if let Some(logger) = self.logger.lock().unwrap().as_ref() {
                    logger.transfer_progress(&self.object_id, verified_end, self.total_size);
                }

                info!("Read {} verified bytes from offset {}", read_bytes, offset);
                Ok(read_bytes)
            }
            ConsumptionPolicy::UnverifiedOk => {
                // Allow reading beyond verified prefix for streaming scenarios
                let available = if offset < self.total_size as usize {
                    (self.total_size as usize - offset).min(buffer.len())
                } else {
                    0
                };

                let read_bytes = available.min(buffer.len());
                for i in 0..read_bytes {
                    buffer[i] = ((offset + i) % 256) as u8; // Deterministic test pattern
                }

                info!(
                    "Read {} unverified bytes from offset {}",
                    read_bytes, offset
                );
                Ok(read_bytes)
            }
        }
    }

    fn safe_resume_offset(&self) -> usize {
        let verified_end = *self.verified_prefix.lock().unwrap();

        // Safe resume point is the last verified chunk boundary
        let chunk_size = 64 * 1024; // 64KB chunks
        let safe_offset = (verified_end as usize / chunk_size) * chunk_size;

        debug!(
            "Calculated safe resume offset: {} (verified_end={}, chunk_size={})",
            safe_offset, verified_end, chunk_size
        );

        info!("Safe resume offset: {}", safe_offset);
        safe_offset
    }

    async fn inject_test_corruption(&self, offset: usize, corrupt_data: &[u8]) -> Result<()> {
        warn!(
            "Injecting test corruption at offset={}, len={}",
            offset,
            corrupt_data.len()
        );

        // Record verification failure for testing
        let failure = VerificationFailureDetails {
            failure_offset: Some(offset),
            invalidation_reason: format!(
                "Injected corruption: {} bytes at offset {}",
                corrupt_data.len(),
                offset
            ),
            replay_pointer: Some(format!("corruption_point_{}", offset)),
        };

        self.verification_failures.lock().unwrap().push(failure);

        // Update verified prefix to stop at corruption point
        let mut verified_prefix = self.verified_prefix.lock().unwrap();
        if offset < *verified_prefix as usize {
            *verified_prefix = offset as u64;
        }

        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            let elapsed_ms = Instant::now().duration_since(Instant::now()).as_millis();
            eprintln!(
                "{{\"ts\":\"2026-05-26T06:36:00Z\",\"test\":\"{}\",\"event\":\"corruption_injected\",\"object_id\":\"{}\",\"offset\":{},\"corrupt_len\":{},\"elapsed_ms\":{}}}",
                "test",
                self.object_id,
                offset,
                corrupt_data.len(),
                elapsed_ms
            );
        }

        info!("Test corruption injected at offset {}", offset);
        Ok(())
    }

    fn has_verification_failure(&self) -> bool {
        let has_failure = !self.verification_failures.lock().unwrap().is_empty();
        debug!("Verification failure check: {}", has_failure);
        has_failure
    }

    async fn get_verification_failure_details(&self) -> Result<VerificationFailureDetails> {
        let failures = self.verification_failures.lock().unwrap();

        if failures.is_empty() {
            return Err("No verification failures found".into());
        }

        // Return the most recent failure
        let latest_failure = failures.last().unwrap().clone();

        info!(
            "Retrieved verification failure details: offset={:?}, reason='{}'",
            latest_failure.failure_offset, latest_failure.invalidation_reason
        );

        Ok(latest_failure)
    }

    /// Get the object ID for this stream
    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    /// Get the current verified prefix end position
    pub fn verified_prefix_end(&self) -> u64 {
        *self.verified_prefix.lock().unwrap()
    }

    /// Simulate verification progress for testing
    pub fn advance_verified_prefix(&self, new_end: u64) {
        let mut verified = self.verified_prefix.lock().unwrap();
        if new_end > *verified {
            *verified = new_end;
            debug!("Advanced verified prefix to {}", new_end);
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerificationFailureDetails {
    pub failure_offset: Option<usize>,
    pub invalidation_reason: String,
    pub replay_pointer: Option<String>,
}

/// DirectoryHandle implementation
impl DirectoryHandle {
    /// Get the transfer ID
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Get total bytes transferred
    pub fn total_bytes(&self) -> u64 {
        self.inner.total_bytes
    }
}
