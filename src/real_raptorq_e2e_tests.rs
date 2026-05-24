//! [br-e2e-7] Real RaptorQ Encode→Decode E2E Tests
//!
//! Real-service E2E tests for RaptorQ forward error correction using actual
//! encoding and decoding operations. Tests complete encode→decode cycles,
//! symbol loss recovery, and multi-block operations with file fixtures.
//!
//! Uses rch + CARGO_TARGET_DIR=/tmp/rch_target_pane1_e2e for end-to-end validation
//! with actual RaptorQ implementations rather than mocks.

#[cfg(any(test, feature = "test-internals"))]
mod raptorq_e2e_tests {
    use crate::config::{EncodingConfig, RaptorQConfig, ResourceConfig};
    use crate::cx::{Cx, CxBuilder};
    use crate::raptorq::{
        RaptorQReceiverBuilder, RaptorQSender, RaptorQSenderBuilder, ReceiveOutcome, SendOutcome,
    };
    use crate::runtime::RuntimeBuilder;
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::transport::memory::{MemorySymbolSink, MemorySymbolStream};
    use crate::types::resource::PoolConfig;
    use crate::types::symbol::{ObjectId, ObjectParams};
    use serde_json;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::{TempDir, tempdir};

    /// Real RaptorQ encoder-decoder pair for E2E testing
    pub struct RealRaptorQCodec {
        config: RaptorQConfig,
        temp_dir: TempDir,
        stats: Arc<RaptorQE2EStats>,
    }

    /// Configuration for RaptorQ E2E testing
    #[derive(Debug, Clone)]
    pub struct RaptorQE2EConfig {
        pub symbol_size: u16,
        pub max_block_size: usize,
        pub repair_overhead: f64,
        pub pool_size: usize,
        pub test_with_symbol_loss: bool,
        pub symbol_loss_rate: f64,
    }

    impl Default for RaptorQE2EConfig {
        fn default() -> Self {
            Self {
                symbol_size: 1024,    // 1KB symbols
                max_block_size: 8192, // 8KB blocks
                repair_overhead: 0.1, // 10% repair symbols
                pool_size: 256,       // Symbol pool size
                test_with_symbol_loss: true,
                symbol_loss_rate: 0.05, // 5% symbol loss
            }
        }
    }

    /// Statistics for RaptorQ E2E operations
    #[derive(Debug, Default)]
    pub struct RaptorQE2EStats {
        pub objects_encoded: AtomicU64,
        pub objects_decoded: AtomicU64,
        pub source_symbols_generated: AtomicU64,
        pub repair_symbols_generated: AtomicU64,
        pub symbols_transmitted: AtomicU64,
        pub symbols_received: AtomicU64,
        pub symbols_lost: AtomicU64,
        pub decode_successes: AtomicU64,
        pub decode_failures: AtomicU64,
        pub bytes_encoded: AtomicU64,
        pub bytes_decoded: AtomicU64,
    }

    /// Enhanced logger for RaptorQ E2E tests
    pub struct RaptorQE2ELogger {
        events: Arc<Mutex<Vec<RaptorQLogEvent>>>,
        start_time: Instant,
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct RaptorQLogEvent {
        pub timestamp: u64,
        pub event_type: String,
        pub object_id: Option<String>,
        pub operation: String, // "encode", "decode", "transmit", "receive"
        pub source_symbols: Option<usize>,
        pub repair_symbols: Option<usize>,
        pub symbols_sent: Option<usize>,
        pub symbols_received: Option<usize>,
        pub symbols_lost: Option<usize>,
        pub data_size: Option<usize>,
        pub success: bool,
        pub error: Option<String>,
        pub details: HashMap<String, serde_json::Value>,
    }

    impl RaptorQE2ELogger {
        pub fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                start_time: Instant::now(),
            }
        }

        pub fn log_encode_start(&self, object_id: &ObjectId, data_size: usize) {
            let mut details = HashMap::new();
            details.insert(
                "encode_start_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    self.start_time.elapsed().as_millis() as u64,
                )),
            );

            let event = RaptorQLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "encode_start".to_string(),
                object_id: Some(format!("{:?}", object_id)),
                operation: "encode".to_string(),
                source_symbols: None,
                repair_symbols: None,
                symbols_sent: None,
                symbols_received: None,
                symbols_lost: None,
                data_size: Some(data_size),
                success: true,
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_encode_complete(&self, outcome: &SendOutcome) {
            let mut details = HashMap::new();
            details.insert(
                "encode_complete_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    self.start_time.elapsed().as_millis() as u64,
                )),
            );

            let event = RaptorQLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "encode_complete".to_string(),
                object_id: Some(format!("{:?}", outcome.object_id)),
                operation: "encode".to_string(),
                source_symbols: Some(outcome.source_symbols),
                repair_symbols: Some(outcome.repair_symbols),
                symbols_sent: Some(outcome.symbols_sent),
                symbols_received: None,
                symbols_lost: None,
                data_size: None,
                success: true,
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_decode_start(&self, object_id: &ObjectId, symbols_available: usize) {
            let mut details = HashMap::new();
            details.insert(
                "decode_start_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    self.start_time.elapsed().as_millis() as u64,
                )),
            );

            let event = RaptorQLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "decode_start".to_string(),
                object_id: Some(format!("{:?}", object_id)),
                operation: "decode".to_string(),
                source_symbols: None,
                repair_symbols: None,
                symbols_sent: None,
                symbols_received: Some(symbols_available),
                symbols_lost: None,
                data_size: None,
                success: true,
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_decode_complete(&self, outcome: &ReceiveOutcome, object_id: &ObjectId) {
            let mut details = HashMap::new();
            details.insert(
                "decode_complete_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    self.start_time.elapsed().as_millis() as u64,
                )),
            );
            details.insert(
                "authenticated".to_string(),
                serde_json::Value::Bool(outcome.authenticated),
            );

            let event = RaptorQLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "decode_complete".to_string(),
                object_id: Some(format!("{:?}", object_id)),
                operation: "decode".to_string(),
                source_symbols: None,
                repair_symbols: None,
                symbols_sent: None,
                symbols_received: Some(outcome.symbols_received),
                symbols_lost: None,
                data_size: Some(outcome.data.len()),
                success: true,
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_symbol_loss(
            &self,
            object_id: &ObjectId,
            symbols_lost: usize,
            total_symbols: usize,
        ) {
            let mut details = HashMap::new();
            details.insert(
                "loss_rate".to_string(),
                serde_json::Value::Number(
                    serde_json::Number::from_f64(symbols_lost as f64 / total_symbols as f64)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ),
            );

            let event = RaptorQLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "symbol_loss".to_string(),
                object_id: Some(format!("{:?}", object_id)),
                operation: "transmit".to_string(),
                source_symbols: None,
                repair_symbols: None,
                symbols_sent: None,
                symbols_received: Some(total_symbols - symbols_lost),
                symbols_lost: Some(symbols_lost),
                data_size: None,
                success: true,
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_error(&self, object_id: Option<&ObjectId>, operation: &str, error: &str) {
            let event = RaptorQLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "error".to_string(),
                object_id: object_id.map(|id| format!("{:?}", id)),
                operation: operation.to_string(),
                source_symbols: None,
                repair_symbols: None,
                symbols_sent: None,
                symbols_received: None,
                symbols_lost: None,
                data_size: None,
                success: false,
                error: Some(error.to_string()),
                details: HashMap::new(),
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn export_json(&self) -> String {
            if let Ok(events) = self.events.lock() {
                serde_json::to_string_pretty(&*events).unwrap_or_else(|_| "[]".to_string())
            } else {
                "[]".to_string()
            }
        }

        pub fn get_event_count(&self) -> usize {
            if let Ok(events) = self.events.lock() {
                events.len()
            } else {
                0
            }
        }
    }

    impl RealRaptorQCodec {
        /// Create new real RaptorQ codec for E2E testing
        pub fn new(test_config: RaptorQE2EConfig) -> Result<Self, Box<dyn std::error::Error>> {
            // Validate environment for real service testing
            Self::validate_test_environment()?;

            let temp_dir = tempdir()?;

            let config = RaptorQConfig {
                encoding: EncodingConfig {
                    symbol_size: test_config.symbol_size,
                    max_block_size: test_config.max_block_size,
                    repair_overhead: test_config.repair_overhead,
                },
                resources: ResourceConfig {
                    symbol_pool_size: test_config.pool_size,
                },
            };

            Ok(Self {
                config,
                temp_dir,
                stats: Arc::new(RaptorQE2EStats::default()),
            })
        }

        /// Validate environment is safe for real service testing
        fn validate_test_environment() -> Result<(), String> {
            if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                return Err(
                    "Cannot run real RaptorQ E2E tests in production environment".to_string(),
                );
            }

            if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
                return Err(
                    "Set REAL_SERVICE_TESTS=true to enable real service testing".to_string()
                );
            }

            Ok(())
        }

        pub fn stats(&self) -> Arc<RaptorQE2EStats> {
            self.stats.clone()
        }

        /// Create test fixture files
        pub fn create_test_fixtures(&self) -> Result<Vec<(PathBuf, Vec<u8>)>, std::io::Error> {
            let mut fixtures = Vec::new();

            // Small file fixture
            let small_data = b"Hello, RaptorQ World! This is a small test file.".repeat(10);
            let small_path = self.temp_dir.path().join("small_test.txt");
            fs::write(&small_path, &small_data)?;
            fixtures.push((small_path, small_data));

            // Medium file fixture
            let medium_data =
                b"This is a medium-sized test file for RaptorQ encoding/decoding. ".repeat(100);
            let medium_path = self.temp_dir.path().join("medium_test.txt");
            fs::write(&medium_path, &medium_data)?;
            fixtures.push((medium_path, medium_data));

            // Large file fixture
            let large_data = (0u8..255).cycle().take(10240).collect::<Vec<u8>>();
            let large_path = self.temp_dir.path().join("large_test.bin");
            fs::write(&large_path, &large_data)?;
            fixtures.push((large_path, large_data));

            Ok(fixtures)
        }

        /// Perform encode→decode cycle with optional symbol loss simulation
        pub async fn encode_decode_cycle(
            &self,
            cx: &Cx,
            object_id: ObjectId,
            data: &[u8],
            simulate_loss: bool,
            loss_rate: f64,
            logger: &RaptorQE2ELogger,
        ) -> Result<ReceiveOutcome, Box<dyn std::error::Error>> {
            // Create memory transport
            let sink = MemorySymbolSink::new();
            let stream_data = sink.data();

            // Encode phase
            logger.log_encode_start(&object_id, data.len());
            let mut sender = RaptorQSenderBuilder::new()
                .config(self.config.clone())
                .transport(sink)
                .build()?;

            let send_outcome = sender.send_object(cx, object_id, data)?;
            logger.log_encode_complete(&send_outcome);

            self.stats.objects_encoded.fetch_add(1, Ordering::Relaxed);
            self.stats
                .source_symbols_generated
                .fetch_add(send_outcome.source_symbols as u64, Ordering::Relaxed);
            self.stats
                .repair_symbols_generated
                .fetch_add(send_outcome.repair_symbols as u64, Ordering::Relaxed);
            self.stats
                .symbols_transmitted
                .fetch_add(send_outcome.symbols_sent as u64, Ordering::Relaxed);
            self.stats
                .bytes_encoded
                .fetch_add(data.len() as u64, Ordering::Relaxed);

            // Simulate symbol loss if requested
            let stream = if simulate_loss && loss_rate > 0.0 {
                let original_symbols = stream_data.symbols().len();
                let symbols_to_lose = (original_symbols as f64 * loss_rate).round() as usize;

                logger.log_symbol_loss(&object_id, symbols_to_lose, original_symbols);
                self.stats
                    .symbols_lost
                    .fetch_add(symbols_to_lose as u64, Ordering::Relaxed);

                MemorySymbolStream::with_loss(stream_data, symbols_to_lose)
            } else {
                MemorySymbolStream::new(stream_data)
            };

            let symbols_available = stream.available_symbols();
            self.stats
                .symbols_received
                .fetch_add(symbols_available as u64, Ordering::Relaxed);

            // Decode phase
            logger.log_decode_start(&object_id, symbols_available);
            let mut receiver = RaptorQReceiverBuilder::new()
                .config(self.config.clone())
                .transport(stream)
                .build()?;

            match receiver.receive_object(cx, object_id).await {
                Ok(receive_outcome) => {
                    logger.log_decode_complete(&receive_outcome, &object_id);

                    self.stats.objects_decoded.fetch_add(1, Ordering::Relaxed);
                    self.stats.decode_successes.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_decoded
                        .fetch_add(receive_outcome.data.len() as u64, Ordering::Relaxed);

                    Ok(receive_outcome)
                }
                Err(e) => {
                    logger.log_error(Some(&object_id), "decode", &e.to_string());
                    self.stats.decode_failures.fetch_add(1, Ordering::Relaxed);
                    Err(Box::new(e))
                }
            }
        }
    }

    /// Production safety guard - validates environment
    fn validate_raptorq_e2e_environment() -> Result<(), String> {
        if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            return Err("Real RaptorQ E2E tests blocked in production".to_string());
        }

        if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
            return Err("Set REAL_SERVICE_TESTS=true to enable".to_string());
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_raptorq_basic_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
        timeout(Duration::from_secs(120), async {
            validate_raptorq_e2e_environment()?;

            let runtime = RuntimeBuilder::new().build()?;
            let cx_builder = CxBuilder::new(&runtime);
            let cx = cx_builder.build();

            let logger = RaptorQE2ELogger::new();
            let codec = RealRaptorQCodec::new(RaptorQE2EConfig::default())?;

            // Test basic encode→decode cycle
            let test_data = b"Hello, RaptorQ! This is a test message for encode/decode verification.";
            let object_id = ObjectId::new();

            let receive_outcome = codec
                .encode_decode_cycle(
                    &cx, object_id, test_data, false, // No symbol loss
                    0.0, &logger,
                )
                .await?;

            // Verify decoded data matches original
            assert_eq!(
                &receive_outcome.data, test_data,
                "Decoded data should match original"
            );
            assert!(
                receive_outcome.symbols_received > 0,
                "Should have received symbols"
            );

            // Verify statistics
            let stats = codec.stats();
            assert_eq!(
                stats.objects_encoded.load(Ordering::Relaxed),
                1,
                "Should have encoded one object"
            );
            assert_eq!(
                stats.objects_decoded.load(Ordering::Relaxed),
                1,
                "Should have decoded one object"
            );
            assert_eq!(
                stats.decode_successes.load(Ordering::Relaxed),
                1,
                "Should have one successful decode"
            );
            assert_eq!(
                stats.bytes_encoded.load(Ordering::Relaxed),
                test_data.len() as u64,
                "Should track encoded bytes"
            );
            assert_eq!(
                stats.bytes_decoded.load(Ordering::Relaxed),
                test_data.len() as u64,
                "Should track decoded bytes"
            );

            eprintln!(
                "RaptorQ Basic E2E structured log:\n{}",
                logger.export_json()
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        }).await
        .map_err(|_| "RaptorQ basic encode/decode test timed out after 120 seconds".into())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_raptorq_with_symbol_loss() -> Result<(), Box<dyn std::error::Error>> {
        validate_raptorq_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = RaptorQE2ELogger::new();
        let test_config = RaptorQE2EConfig {
            repair_overhead: 0.2, // 20% repair symbols for loss tolerance
            ..Default::default()
        };
        let codec = RealRaptorQCodec::new(test_config)?;

        // Test encode→decode with symbol loss
        let test_data = b"This is a longer test message that will be encoded into multiple symbols, some of which will be lost during transmission to test RaptorQ's error correction capabilities.";
        let object_id = ObjectId::new();
        let loss_rate = 0.1; // 10% symbol loss

        let receive_outcome = codec
            .encode_decode_cycle(
                &cx, object_id, test_data, true, // Simulate symbol loss
                loss_rate, &logger,
            )
            .await?;

        // Verify decoded data matches original despite symbol loss
        assert_eq!(
            &receive_outcome.data, test_data,
            "Decoded data should match original despite symbol loss"
        );
        assert!(
            receive_outcome.symbols_received > 0,
            "Should have received symbols"
        );

        // Verify statistics show symbol loss
        let stats = codec.stats();
        assert!(
            stats.symbols_lost.load(Ordering::Relaxed) > 0,
            "Should have lost some symbols"
        );
        assert_eq!(
            stats.decode_successes.load(Ordering::Relaxed),
            1,
            "Should successfully decode despite losses"
        );

        eprintln!(
            "RaptorQ Symbol Loss E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_raptorq_file_fixtures() -> Result<(), Box<dyn std::error::Error>> {
        validate_raptorq_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = RaptorQE2ELogger::new();
        let codec = RealRaptorQCodec::new(RaptorQE2EConfig::default())?;

        // Create test fixtures
        let fixtures = codec.create_test_fixtures()?;

        for (fixture_path, fixture_data) in &fixtures {
            let object_id = ObjectId::new();

            let receive_outcome = codec
                .encode_decode_cycle(
                    &cx,
                    object_id,
                    fixture_data,
                    false, // No symbol loss for file fixtures
                    0.0,
                    &logger,
                )
                .await?;

            // Verify decoded data matches fixture
            assert_eq!(
                &receive_outcome.data,
                fixture_data,
                "Decoded data should match fixture file: {}",
                fixture_path.display()
            );

            eprintln!(
                "Successfully encoded/decoded fixture: {} ({} bytes)",
                fixture_path.display(),
                fixture_data.len()
            );
        }

        // Verify statistics for all fixtures
        let stats = codec.stats();
        assert_eq!(
            stats.objects_encoded.load(Ordering::Relaxed),
            fixtures.len() as u64,
            "Should have encoded all fixture files"
        );
        assert_eq!(
            stats.objects_decoded.load(Ordering::Relaxed),
            fixtures.len() as u64,
            "Should have decoded all fixture files"
        );

        eprintln!(
            "RaptorQ File Fixtures E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_raptorq_large_data_multi_block() -> Result<(), Box<dyn std::error::Error>> {
        validate_raptorq_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = RaptorQE2ELogger::new();
        let test_config = RaptorQE2EConfig {
            max_block_size: 2048, // Smaller blocks to force multi-block encoding
            symbol_size: 256,
            repair_overhead: 0.15, // 15% repair symbols
            ..Default::default()
        };
        let codec = RealRaptorQCodec::new(test_config)?;

        // Generate large test data that will span multiple blocks
        let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let object_id = ObjectId::new();

        let receive_outcome = codec
            .encode_decode_cycle(
                &cx,
                object_id,
                &large_data,
                true, // Simulate symbol loss
                0.05, // 5% loss rate
                &logger,
            )
            .await?;

        // Verify decoded data matches original for large multi-block data
        assert_eq!(
            &receive_outcome.data, &large_data,
            "Large multi-block data should decode correctly"
        );
        assert!(
            receive_outcome.symbols_received > 10,
            "Should have received many symbols"
        );

        // Verify statistics for large data
        let stats = codec.stats();
        assert!(
            stats.source_symbols_generated.load(Ordering::Relaxed) > 10,
            "Should generate multiple source symbols for large data"
        );
        assert!(
            stats.repair_symbols_generated.load(Ordering::Relaxed) > 0,
            "Should generate repair symbols"
        );

        eprintln!(
            "RaptorQ Large Data E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }
}

#[cfg(any(test, feature = "test-internals"))]
pub use raptorq_e2e_tests::*;
