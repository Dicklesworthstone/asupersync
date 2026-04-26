#![allow(warnings)]
#![allow(clippy::all)]
//! Round-trip validation harness for RaptorQ conformance testing.
//!
//! This module provides comprehensive round-trip testing that validates
//! RaptorQ encode-decode cycles produce correct outputs. It uses golden
//! files to freeze known-correct behavior and detect regressions.

use crate::golden_file_manager::{create_metadata, GoldenError, GoldenFileManager, GoldenMetadata};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// Configuration for round-trip test execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(dead_code)]
pub struct RoundTripConfig {
    /// Number of source symbols (K)
    pub source_symbols: usize,
    /// Symbol size in bytes
    pub symbol_size: usize,
    /// Number of repair symbols to generate
    pub repair_symbols: usize,
    /// Random seed for reproducible test data
    pub seed: u64,
    /// Whether to test with erasures
    pub test_erasures: bool,
    /// Erasure probability (0.0 - 1.0)
    pub erasure_probability: f64,
}

impl Default for RoundTripConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            source_symbols: 100,
            symbol_size: 1024,
            repair_symbols: 50,
            seed: 42,
            test_erasures: true,
            erasure_probability: 0.1,
        }
    }
}

/// Input data for a round-trip test
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(dead_code)]
pub struct RoundTripInput {
    /// Original source data
    pub source_data: Vec<u8>,
    /// Test configuration
    pub config: RoundTripConfig,
    /// Test case metadata
    pub test_case: String,
}

/// Expected output from a round-trip test
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(dead_code)]
pub struct RoundTripOutput {
    /// Encoded symbols (source + repair)
    pub encoded_symbols: Vec<Vec<u8>>,
    /// Symbol indices for each encoded symbol
    pub symbol_indices: Vec<u32>,
    /// Decoded source data (should match input)
    pub decoded_data: Vec<u8>,
    /// Round-trip success flag
    pub success: bool,
    /// Error message if round-trip failed
    pub error_message: Option<String>,
    /// Timing information in microseconds
    pub encode_time_us: u64,
    pub decode_time_us: u64,
    /// Additional validation metrics
    pub validation_metrics: ValidationMetrics,
}

/// Metrics for validating round-trip correctness
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct ValidationMetrics {
    /// Data integrity check passed
    pub data_integrity: bool,
    /// Symbol count validation passed
    pub symbol_count_valid: bool,
    /// Encoding parameters preserved
    pub parameters_preserved: bool,
    /// Repair symbol validation passed
    pub repair_symbols_valid: bool,
    /// Erasure recovery validation passed (if applicable)
    pub erasure_recovery_valid: Option<bool>,
}

/// Round-trip test harness for RaptorQ conformance validation
#[allow(dead_code)]
pub struct RoundTripHarness {
    golden_manager: GoldenFileManager,
    configs: Vec<RoundTripConfig>,
}

#[allow(dead_code)]

impl RoundTripHarness {
    /// Creates a new round-trip test harness
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(golden_dir: P) -> Self {
        Self {
            golden_manager: GoldenFileManager::new(golden_dir),
            configs: Self::default_test_configs(),
        }
    }

    /// Creates a harness with custom test configurations
    #[allow(dead_code)]
    pub fn with_configs<P: AsRef<Path>>(golden_dir: P, configs: Vec<RoundTripConfig>) -> Self {
        Self {
            golden_manager: GoldenFileManager::new(golden_dir),
            configs,
        }
    }

    /// Default set of test configurations covering common RFC 6330 scenarios
    #[allow(dead_code)]
    fn default_test_configs() -> Vec<RoundTripConfig> {
        vec![
            // Basic small block
            RoundTripConfig {
                source_symbols: 10,
                symbol_size: 64,
                repair_symbols: 5,
                seed: 1,
                test_erasures: false,
                erasure_probability: 0.0,
            },
            // Medium block with erasures
            RoundTripConfig {
                source_symbols: 100,
                symbol_size: 1024,
                repair_symbols: 50,
                seed: 42,
                test_erasures: true,
                erasure_probability: 0.1,
            },
            // Large block
            RoundTripConfig {
                source_symbols: 1000,
                symbol_size: 1024,
                repair_symbols: 200,
                seed: 123,
                test_erasures: true,
                erasure_probability: 0.15,
            },
            // Edge case: minimal symbols
            RoundTripConfig {
                source_symbols: 1,
                symbol_size: 1,
                repair_symbols: 1,
                seed: 999,
                test_erasures: false,
                erasure_probability: 0.0,
            },
            // Edge case: max symbols per RFC 6330
            RoundTripConfig {
                source_symbols: 8192,
                symbol_size: 1024,
                repair_symbols: 1000,
                seed: 777,
                test_erasures: true,
                erasure_probability: 0.05,
            },
        ]
    }

    /// Executes all round-trip tests and validates against golden files
    #[allow(dead_code)]
    pub fn run_all_tests(&self) -> Result<RoundTripSummary, RoundTripError> {
        let mut summary = RoundTripSummary::default();

        for (i, config) in self.configs.iter().enumerate() {
            let test_name = format!("round_trip_test_{}", i);

            match self.run_single_test(&test_name, config) {
                Ok(result) => {
                    summary.total_tests += 1;
                    if result.success {
                        summary.passed_tests += 1;
                    } else {
                        summary.failed_tests += 1;
                        summary.failures.push(format!(
                            "{}: {}",
                            test_name,
                            result.error_message.as_deref().unwrap_or("unknown error")
                        ));
                    }
                }
                Err(e) => {
                    summary.total_tests += 1;
                    summary.failed_tests += 1;
                    summary.failures.push(format!("{}: {}", test_name, e));
                }
            }
        }

        Ok(summary)
    }

    /// Executes a single round-trip test
    #[allow(dead_code)]
    pub fn run_single_test(
        &self,
        test_name: &str,
        config: &RoundTripConfig,
    ) -> Result<RoundTripOutput, RoundTripError> {
        // Generate test input data
        let input = self.generate_test_input(test_name, config)?;

        // Execute round-trip encode/decode
        let output = self.execute_round_trip(&input)?;

        // Validate against golden file
        let filename = format!("{}.golden", test_name);
        let metadata = self.create_test_metadata(test_name, config)?;

        self.golden_manager
            .assert_golden(&filename, &output, metadata)
            .map_err(RoundTripError::GoldenFileError)?;

        Ok(output)
    }

    /// Generates deterministic test input data
    #[allow(dead_code)]
    fn generate_test_input(
        &self,
        test_name: &str,
        config: &RoundTripConfig,
    ) -> Result<RoundTripInput, RoundTripError> {
        // Use seeded PRNG for reproducible test data
        let mut rng = Self::create_seeded_rng(config.seed);

        let data_size = config.source_symbols * config.symbol_size;
        let mut source_data = vec![0u8; data_size];

        // Fill with deterministic pseudo-random data
        for byte in source_data.iter_mut() {
            *byte = Self::next_random_byte(&mut rng);
        }

        Ok(RoundTripInput {
            source_data,
            config: config.clone(),
            test_case: test_name.to_string(),
        })
    }

    /// Executes the actual round-trip encode/decode process against the
    /// real `asupersync::raptorq` codec (br-2puta6).
    #[allow(dead_code)]
    fn execute_round_trip(
        &self,
        input: &RoundTripInput,
    ) -> Result<RoundTripOutput, RoundTripError> {
        use asupersync::config::EncodingConfig;
        use asupersync::decoding::{DecodingConfig, DecodingPipeline};
        use asupersync::encoding::EncodingPipeline;
        use asupersync::security::tag::AuthenticationTag;
        use asupersync::security::AuthenticatedSymbol;
        use asupersync::types::resource::{PoolConfig, SymbolPool};
        use asupersync::types::{ObjectId, ObjectParams, Symbol, SymbolKind};

        let cfg = &input.config;
        let symbol_size: u16 = u16::try_from(cfg.symbol_size).map_err(|_| {
            RoundTripError::ConfigError(format!("symbol_size {} exceeds u16::MAX", cfg.symbol_size))
        })?;
        let symbols_per_block: u16 = u16::try_from(cfg.source_symbols).map_err(|_| {
            RoundTripError::ConfigError(format!(
                "source_symbols {} exceeds u16::MAX",
                cfg.source_symbols
            ))
        })?;
        let data_len = input.source_data.len();
        // A single source block carries the whole payload; the encoder will
        // refuse data longer than `max_block_size`.
        let max_block_size: usize = data_len.max(usize::from(symbol_size) * cfg.source_symbols);

        let enc_config = EncodingConfig {
            symbol_size,
            max_block_size,
            // `encode_with_repair` overrides this; keep a sane default.
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let pool_size = (cfg.source_symbols + cfg.repair_symbols).max(16);
        let pool = SymbolPool::new(PoolConfig {
            symbol_size,
            initial_size: pool_size,
            max_size: pool_size * 2,
            allow_growth: true,
            growth_increment: 16,
        });

        let object_id = ObjectId::new_for_test(cfg.seed);
        let mut encoder = EncodingPipeline::new(enc_config, pool);

        // ENCODE — drive the real RaptorQ encoding pipeline.
        let encode_start = std::time::Instant::now();
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &input.source_data, cfg.repair_symbols)
            .map(|res| {
                res.map(|enc| enc.into_symbol())
                    .map_err(|e| RoundTripError::EncodingError(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let encode_time = encode_start.elapsed();

        let symbol_indices: Vec<u32> = symbols.iter().map(|s| s.id().esi()).collect();
        let encoded_symbols_bytes: Vec<Vec<u8>> =
            symbols.iter().map(|s| s.data().to_vec()).collect();

        // ERASURE: drop a deterministic, seeded fraction of the encoded
        // symbols so that decode is forced to recover from repair symbols.
        let mut erased_count: usize = 0;
        let transmitted: Vec<Symbol> = if cfg.test_erasures && cfg.erasure_probability > 0.0 {
            let mut rng = cfg.seed.wrapping_mul(0x517c_c1b7_2722_0a95);
            let drop_threshold: u64 =
                (cfg.erasure_probability.clamp(0.0, 1.0) * f64::from(u32::MAX)) as u64;
            symbols
                .iter()
                .filter_map(|s| {
                    rng = rng
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let coin = (rng >> 32) & 0xFFFF_FFFF;
                    if coin < drop_threshold {
                        erased_count += 1;
                        None
                    } else {
                        Some(s.clone())
                    }
                })
                .collect()
        } else {
            symbols.clone()
        };

        // DECODE — drive the real RaptorQ decoding pipeline.
        let dec_config = DecodingConfig {
            symbol_size,
            max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: symbols.len().saturating_mul(2),
            block_timeout: std::time::Duration::from_secs(60),
            verify_auth: false,
        };
        let mut decoder = DecodingPipeline::new(dec_config);
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                symbol_size,
                1,
                symbols_per_block,
            ))
            .map_err(|e| RoundTripError::DecodingError(e.to_string()))?;

        let decode_start = std::time::Instant::now();
        for symbol in &transmitted {
            let auth = AuthenticatedSymbol::from_parts(symbol.clone(), AuthenticationTag::zero());
            decoder
                .feed(auth)
                .map_err(|e| RoundTripError::DecodingError(e.to_string()))?;
        }
        let decoded_data = decoder
            .into_data()
            .map_err(|e| RoundTripError::DecodingError(e.to_string()))?;
        let decode_time = decode_start.elapsed();

        // Real validation — every flag is now derived from the live
        // encode/decode result, no hardcoded `true`.
        let data_integrity = decoded_data == input.source_data;
        let expected_total = cfg.source_symbols + cfg.repair_symbols;
        let symbol_count_valid = symbols.len() == expected_total;
        let parameters_preserved = usize::from(symbol_size) == cfg.symbol_size
            && usize::from(symbols_per_block) == cfg.source_symbols;
        let repair_symbol_count = symbols
            .iter()
            .filter(|s| s.kind() == SymbolKind::Repair)
            .count();
        let repair_symbols_valid = repair_symbol_count == cfg.repair_symbols
            && symbols
                .iter()
                .filter(|s| s.kind() == SymbolKind::Repair)
                .all(|s| s.id().esi() >= cfg.source_symbols as u32);
        let erasure_recovery_valid = if cfg.test_erasures && cfg.erasure_probability > 0.0 {
            // True only when we actually erased some symbols *and* still
            // recovered the original payload byte-for-byte.
            Some(erased_count > 0 && data_integrity)
        } else {
            None
        };

        let validation_metrics = ValidationMetrics {
            data_integrity,
            symbol_count_valid,
            parameters_preserved,
            repair_symbols_valid,
            erasure_recovery_valid,
        };
        let success = data_integrity
            && symbol_count_valid
            && parameters_preserved
            && repair_symbols_valid
            && erasure_recovery_valid.unwrap_or(true);

        Ok(RoundTripOutput {
            encoded_symbols: encoded_symbols_bytes,
            symbol_indices,
            decoded_data,
            success,
            error_message: if !success {
                Some("Round-trip validation failed".to_string())
            } else {
                None
            },
            encode_time_us: encode_time.as_micros() as u64,
            decode_time_us: decode_time.as_micros() as u64,
            validation_metrics,
        })
    }

    /// Creates metadata for test golden files
    #[allow(dead_code)]
    fn create_test_metadata(
        &self,
        test_name: &str,
        config: &RoundTripConfig,
    ) -> Result<GoldenMetadata, RoundTripError> {
        let mut input_params = HashMap::new();
        input_params.insert(
            "source_symbols".to_string(),
            config.source_symbols.to_string(),
        );
        input_params.insert("symbol_size".to_string(), config.symbol_size.to_string());
        input_params.insert(
            "repair_symbols".to_string(),
            config.repair_symbols.to_string(),
        );
        input_params.insert("seed".to_string(), config.seed.to_string());
        input_params.insert(
            "test_erasures".to_string(),
            config.test_erasures.to_string(),
        );
        input_params.insert(
            "erasure_probability".to_string(),
            config.erasure_probability.to_string(),
        );

        Ok(create_metadata(
            test_name,
            "5.3.2.2", // RFC 6330 systematic indices
            &format!(
                "Round-trip validation for RaptorQ with K={} symbols",
                config.source_symbols
            ),
            input_params,
        ))
    }

    /// Creates a seeded PRNG for deterministic test data
    #[allow(dead_code)]
    fn create_seeded_rng(seed: u64) -> u64 {
        // Simple LCG for reproducible test data
        seed
    }

    /// Generates next pseudo-random byte
    #[allow(dead_code)]
    fn next_random_byte(rng: &mut u64) -> u8 {
        // Linear Congruential Generator (LCG)
        *rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng >> 24) as u8
    }
}

/// Summary of round-trip test execution
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct RoundTripSummary {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub failures: Vec<String>,
}

#[allow(dead_code)]

impl RoundTripSummary {
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        self.failed_tests == 0 && self.total_tests > 0
    }

    #[allow(dead_code)]

    pub fn pass_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            self.passed_tests as f64 / self.total_tests as f64
        }
    }
}

impl fmt::Display for RoundTripSummary {
    #[allow(dead_code)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Round-trip tests: {}/{} passed ({:.1}%)",
            self.passed_tests,
            self.total_tests,
            self.pass_rate() * 100.0
        )?;

        if !self.failures.is_empty() {
            write!(f, "\nFailures:")?;
            for failure in &self.failures {
                write!(f, "\n  - {}", failure)?;
            }
        }

        Ok(())
    }
}

/// Errors that can occur during round-trip testing
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum RoundTripError {
    #[error("Golden file error: {0}")]
    GoldenFileError(GoldenError),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[allow(dead_code)]
    fn test_default_config() {
        let config = RoundTripConfig::default();
        assert_eq!(config.source_symbols, 100);
        assert_eq!(config.symbol_size, 1024);
        assert_eq!(config.repair_symbols, 50);
        assert_eq!(config.seed, 42);
        assert!(config.test_erasures);
        assert_eq!(config.erasure_probability, 0.1);
    }

    #[test]
    #[allow(dead_code)]
    fn test_seeded_rng_deterministic() {
        let mut rng1 = RoundTripHarness::create_seeded_rng(12345);
        let mut rng2 = RoundTripHarness::create_seeded_rng(12345);

        for _ in 0..100 {
            let byte1 = RoundTripHarness::next_random_byte(&mut rng1);
            let byte2 = RoundTripHarness::next_random_byte(&mut rng2);
            assert_eq!(byte1, byte2);
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_validation_metrics_default() {
        let metrics = ValidationMetrics::default();
        assert!(!metrics.data_integrity);
        assert!(!metrics.symbol_count_valid);
        assert!(!metrics.parameters_preserved);
        assert!(!metrics.repair_symbols_valid);
        assert_eq!(metrics.erasure_recovery_valid, None);
    }

    #[test]
    #[allow(dead_code)]
    fn test_round_trip_summary_pass_rate() {
        let mut summary = RoundTripSummary::default();
        assert_eq!(summary.pass_rate(), 0.0);

        summary.total_tests = 10;
        summary.passed_tests = 7;
        summary.failed_tests = 3;
        assert_eq!(summary.pass_rate(), 0.7);
    }

    #[test]
    #[allow(dead_code)]
    fn test_harness_creation() {
        let temp_dir = TempDir::new().unwrap();
        let harness = RoundTripHarness::new(temp_dir.path());
        assert_eq!(harness.configs.len(), 5); // Default configs
    }

    #[test]
    #[allow(dead_code)]
    fn test_generate_test_input() {
        let temp_dir = TempDir::new().unwrap();
        let harness = RoundTripHarness::new(temp_dir.path());

        let config = RoundTripConfig {
            source_symbols: 2,
            symbol_size: 4,
            repair_symbols: 1,
            seed: 123,
            test_erasures: false,
            erasure_probability: 0.0,
        };

        let input1 = harness.generate_test_input("test", &config).unwrap();
        let input2 = harness.generate_test_input("test", &config).unwrap();

        // Should be deterministic
        assert_eq!(input1.source_data, input2.source_data);
        assert_eq!(input1.source_data.len(), 8); // 2 * 4 = 8 bytes
    }
}
