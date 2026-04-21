#![allow(clippy::all)]
//! Test fixture generation for RaptorQ golden file testing.
//!
//! This module generates comprehensive test fixtures that cover various
//! RFC 6330 scenarios, edge cases, and regression test cases. Fixtures
//! are deterministic and can be regenerated for golden file updates.

use crate::round_trip_harness::{RoundTripConfig, RoundTripInput};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Categories of test fixtures covering different RFC 6330 aspects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum FixtureCategory {
    /// Basic encoding/decoding scenarios
    BasicOperations,
    /// Edge cases and boundary conditions
    EdgeCases,
    /// Performance and scaling scenarios
    Performance,
    /// Error conditions and recovery
    ErrorHandling,
    /// RFC 6330 specification compliance
    SpecCompliance,
    /// Interoperability test vectors
    Interoperability,
}

#[allow(dead_code)]

impl FixtureCategory {
    /// Returns human-readable description of the category
    #[allow(dead_code)]
    pub fn description(&self) -> &'static str {
        match self {
            Self::BasicOperations => "Basic RaptorQ encode/decode operations",
            Self::EdgeCases => "Boundary conditions and edge cases",
            Self::Performance => "Performance and scaling scenarios",
            Self::ErrorHandling => "Error conditions and recovery paths",
            Self::SpecCompliance => "RFC 6330 specification compliance",
            Self::Interoperability => "Cross-implementation compatibility",
        }
    }

    /// Returns RFC 6330 sections relevant to this category
    #[allow(dead_code)]
    pub fn rfc_sections(&self) -> Vec<&'static str> {
        match self {
            Self::BasicOperations => vec!["5.3.2.1", "5.3.2.2", "5.4"],
            Self::EdgeCases => vec!["5.3.1.2", "5.3.1.3"],
            Self::Performance => vec!["5.6"],
            Self::ErrorHandling => vec!["5.7"],
            Self::SpecCompliance => vec!["4", "5"],
            Self::Interoperability => vec!["6"],
        }
    }
}

/// Test fixture metadata and parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FixtureSpec {
    /// Unique fixture identifier
    pub id: String,
    /// Human-readable fixture name
    pub name: String,
    /// Fixture category
    pub category: FixtureCategory,
    /// Test description
    pub description: String,
    /// RaptorQ configuration
    pub config: RoundTripConfig,
    /// Expected properties and outcomes
    pub expected_properties: FixtureProperties,
    /// Priority level (1=critical, 5=nice-to-have)
    pub priority: u8,
    /// Whether this fixture tests error conditions
    pub expects_error: bool,
    /// Tags for filtering and organization
    pub tags: Vec<String>,
}

/// Expected properties that should be validated for a fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FixtureProperties {
    /// Should succeed without errors
    pub should_succeed: bool,
    /// Expected encoding overhead (repair symbols / source symbols)
    pub expected_overhead_ratio: Option<f64>,
    /// Maximum acceptable encoding time in milliseconds
    pub max_encode_time_ms: Option<u64>,
    /// Maximum acceptable decoding time in milliseconds
    pub max_decode_time_ms: Option<u64>,
    /// Expected memory usage pattern
    pub memory_profile: MemoryProfile,
    /// Cross-implementation compatibility expected
    pub cross_compat: bool,
}

/// Memory usage pattern expectations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum MemoryProfile {
    /// Low memory usage (< 10MB)
    Low,
    /// Moderate memory usage (10-100MB)
    Moderate,
    /// High memory usage (100MB-1GB)
    High,
    /// Very high memory usage (>1GB)
    VeryHigh,
    /// Memory usage scales linearly with input size
    Linear,
    /// Memory usage scales sub-linearly
    SubLinear,
}

/// Fixture generation engine
#[allow(dead_code)]
pub struct FixtureGenerator {
    fixtures: HashMap<FixtureCategory, Vec<FixtureSpec>>,
    output_dir: PathBuf,
}

#[allow(dead_code)]

impl FixtureGenerator {
    /// Creates a new fixture generator
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(output_dir: P) -> Self {
        let mut generator = Self {
            fixtures: HashMap::new(),
            output_dir: output_dir.as_ref().to_path_buf(),
        };
        generator.initialize_default_fixtures();
        generator
    }

    /// Generates all test fixtures and writes them to disk
    #[allow(dead_code)]
    pub fn generate_all_fixtures(
        &self,
    ) -> Result<FixtureGenerationSummary, FixtureGenerationError> {
        let mut summary = FixtureGenerationSummary::default();

        // Ensure output directory exists
        fs::create_dir_all(&self.output_dir)?;

        for (category, fixtures) in &self.fixtures {
            let category_dir = self
                .output_dir
                .join(format!("{:?}", category).to_lowercase());
            fs::create_dir_all(&category_dir)?;

            for fixture in fixtures {
                match self.generate_single_fixture(fixture, &category_dir) {
                    Ok(fixture_path) => {
                        summary.generated_fixtures += 1;
                        summary.generated_files.push(fixture_path);
                    }
                    Err(e) => {
                        summary.failed_fixtures += 1;
                        summary.errors.push(format!("{}: {}", fixture.id, e));
                    }
                }
            }
        }

        Ok(summary)
    }

    /// Generates a single fixture file
    #[allow(dead_code)]
    fn generate_single_fixture(
        &self,
        spec: &FixtureSpec,
        category_dir: &Path,
    ) -> Result<PathBuf, FixtureGenerationError> {
        let input = self.create_fixture_input(spec)?;
        let fixture_path = category_dir.join(format!("{}.json", spec.id));

        let fixture_data = FixtureData {
            spec: spec.clone(),
            input,
            metadata: FixtureMetadata {
                generated_at: chrono::Utc::now(),
                generator_version: env!("CARGO_PKG_VERSION").to_string(),
                rfc_6330_version: "RFC 6330".to_string(),
            },
        };

        let json = serde_json::to_string_pretty(&fixture_data)?;
        fs::write(&fixture_path, json)?;

        Ok(fixture_path)
    }

    /// Creates test input data for a fixture
    #[allow(dead_code)]
    fn create_fixture_input(
        &self,
        spec: &FixtureSpec,
    ) -> Result<RoundTripInput, FixtureGenerationError> {
        let data_size = spec.config.source_symbols * spec.config.symbol_size;
        let source_data = match spec.category {
            FixtureCategory::BasicOperations => {
                self.generate_basic_data(data_size, spec.config.seed)
            }
            FixtureCategory::EdgeCases => self.generate_edge_case_data(data_size, &spec.id),
            FixtureCategory::Performance => {
                self.generate_performance_data(data_size, spec.config.seed)
            }
            FixtureCategory::ErrorHandling => self.generate_error_test_data(data_size, &spec.id),
            FixtureCategory::SpecCompliance => {
                self.generate_spec_test_data(data_size, spec.config.seed)
            }
            FixtureCategory::Interoperability => {
                self.generate_interop_data(data_size, spec.config.seed)
            }
        };

        Ok(RoundTripInput {
            source_data,
            config: spec.config.clone(),
            test_case: spec.name.clone(),
        })
    }

    /// Initializes the default set of test fixtures
    #[allow(dead_code)]
    fn initialize_default_fixtures(&mut self) {
        self.add_basic_operation_fixtures();
        self.add_edge_case_fixtures();
        self.add_performance_fixtures();
        self.add_error_handling_fixtures();
        self.add_spec_compliance_fixtures();
        self.add_interoperability_fixtures();
    }

    /// Adds basic operation test fixtures
    #[allow(dead_code)]
    fn add_basic_operation_fixtures(&mut self) {
        let fixtures = vec![
            FixtureSpec {
                id: "basic_small_block".to_string(),
                name: "Small Block Encoding".to_string(),
                category: FixtureCategory::BasicOperations,
                description: "Basic encoding of small data block".to_string(),
                config: RoundTripConfig {
                    source_symbols: 10,
                    symbol_size: 64,
                    repair_symbols: 5,
                    seed: 1,
                    test_erasures: false,
                    erasure_probability: 0.0,
                },
                expected_properties: FixtureProperties {
                    should_succeed: true,
                    expected_overhead_ratio: Some(0.5),
                    max_encode_time_ms: Some(100),
                    max_decode_time_ms: Some(100),
                    memory_profile: MemoryProfile::Low,
                    cross_compat: true,
                },
                priority: 1,
                expects_error: false,
                tags: vec!["basic".to_string(), "small".to_string()],
            },
            FixtureSpec {
                id: "basic_medium_block".to_string(),
                name: "Medium Block Encoding".to_string(),
                category: FixtureCategory::BasicOperations,
                description: "Standard size block encoding".to_string(),
                config: RoundTripConfig {
                    source_symbols: 100,
                    symbol_size: 1024,
                    repair_symbols: 50,
                    seed: 42,
                    test_erasures: true,
                    erasure_probability: 0.1,
                },
                expected_properties: FixtureProperties {
                    should_succeed: true,
                    expected_overhead_ratio: Some(0.5),
                    max_encode_time_ms: Some(1000),
                    max_decode_time_ms: Some(1000),
                    memory_profile: MemoryProfile::Moderate,
                    cross_compat: true,
                },
                priority: 1,
                expects_error: false,
                tags: vec![
                    "basic".to_string(),
                    "medium".to_string(),
                    "erasures".to_string(),
                ],
            },
        ];

        self.fixtures
            .insert(FixtureCategory::BasicOperations, fixtures);
    }

    /// Adds edge case test fixtures
    #[allow(dead_code)]
    fn add_edge_case_fixtures(&mut self) {
        let fixtures = vec![
            FixtureSpec {
                id: "edge_minimal_symbols".to_string(),
                name: "Minimal Symbol Count".to_string(),
                category: FixtureCategory::EdgeCases,
                description: "Single source symbol edge case".to_string(),
                config: RoundTripConfig {
                    source_symbols: 1,
                    symbol_size: 1,
                    repair_symbols: 1,
                    seed: 999,
                    test_erasures: false,
                    erasure_probability: 0.0,
                },
                expected_properties: FixtureProperties {
                    should_succeed: true,
                    expected_overhead_ratio: Some(1.0),
                    max_encode_time_ms: Some(10),
                    max_decode_time_ms: Some(10),
                    memory_profile: MemoryProfile::Low,
                    cross_compat: true,
                },
                priority: 2,
                expects_error: false,
                tags: vec!["edge".to_string(), "minimal".to_string()],
            },
            FixtureSpec {
                id: "edge_max_symbols".to_string(),
                name: "Maximum Symbol Count".to_string(),
                category: FixtureCategory::EdgeCases,
                description: "Maximum symbols per RFC 6330 limits".to_string(),
                config: RoundTripConfig {
                    source_symbols: 8192,
                    symbol_size: 1024,
                    repair_symbols: 1000,
                    seed: 777,
                    test_erasures: false,
                    erasure_probability: 0.0,
                },
                expected_properties: FixtureProperties {
                    should_succeed: true,
                    expected_overhead_ratio: Some(0.12),
                    max_encode_time_ms: Some(30000),
                    max_decode_time_ms: Some(30000),
                    memory_profile: MemoryProfile::High,
                    cross_compat: true,
                },
                priority: 2,
                expects_error: false,
                tags: vec![
                    "edge".to_string(),
                    "maximum".to_string(),
                    "slow".to_string(),
                ],
            },
        ];

        self.fixtures.insert(FixtureCategory::EdgeCases, fixtures);
    }

    /// Adds performance test fixtures
    #[allow(dead_code)]
    fn add_performance_fixtures(&mut self) {
        let fixtures = vec![FixtureSpec {
            id: "perf_large_block".to_string(),
            name: "Large Block Performance".to_string(),
            category: FixtureCategory::Performance,
            description: "Performance test with large data block".to_string(),
            config: RoundTripConfig {
                source_symbols: 1000,
                symbol_size: 1024,
                repair_symbols: 200,
                seed: 123,
                test_erasures: true,
                erasure_probability: 0.15,
            },
            expected_properties: FixtureProperties {
                should_succeed: true,
                expected_overhead_ratio: Some(0.2),
                max_encode_time_ms: Some(10000),
                max_decode_time_ms: Some(10000),
                memory_profile: MemoryProfile::Moderate,
                cross_compat: true,
            },
            priority: 3,
            expects_error: false,
            tags: vec!["performance".to_string(), "large".to_string()],
        }];

        self.fixtures.insert(FixtureCategory::Performance, fixtures);
    }

    /// Adds error handling test fixtures
    #[allow(dead_code)]
    fn add_error_handling_fixtures(&mut self) {
        let fixtures = vec![FixtureSpec {
            id: "error_high_erasure".to_string(),
            name: "High Erasure Rate".to_string(),
            category: FixtureCategory::ErrorHandling,
            description: "Test recovery with high erasure probability".to_string(),
            config: RoundTripConfig {
                source_symbols: 50,
                symbol_size: 512,
                repair_symbols: 20,
                seed: 456,
                test_erasures: true,
                erasure_probability: 0.5,
            },
            expected_properties: FixtureProperties {
                should_succeed: false, // May fail with high erasure rate
                expected_overhead_ratio: Some(0.4),
                max_encode_time_ms: Some(1000),
                max_decode_time_ms: Some(1000),
                memory_profile: MemoryProfile::Moderate,
                cross_compat: false,
            },
            priority: 3,
            expects_error: true,
            tags: vec!["error".to_string(), "erasure".to_string()],
        }];

        self.fixtures
            .insert(FixtureCategory::ErrorHandling, fixtures);
    }

    /// Adds RFC 6330 specification compliance fixtures
    #[allow(dead_code)]
    fn add_spec_compliance_fixtures(&mut self) {
        let fixtures = vec![FixtureSpec {
            id: "spec_systematic_indices".to_string(),
            name: "Systematic Index Ordering".to_string(),
            category: FixtureCategory::SpecCompliance,
            description: "RFC 6330 Section 5.3.2.2 systematic index compliance".to_string(),
            config: RoundTripConfig {
                source_symbols: 64,
                symbol_size: 256,
                repair_symbols: 32,
                seed: 321,
                test_erasures: false,
                erasure_probability: 0.0,
            },
            expected_properties: FixtureProperties {
                should_succeed: true,
                expected_overhead_ratio: Some(0.5),
                max_encode_time_ms: Some(500),
                max_decode_time_ms: Some(500),
                memory_profile: MemoryProfile::Moderate,
                cross_compat: true,
            },
            priority: 1,
            expects_error: false,
            tags: vec!["spec".to_string(), "systematic".to_string()],
        }];

        self.fixtures
            .insert(FixtureCategory::SpecCompliance, fixtures);
    }

    /// Adds interoperability test fixtures
    #[allow(dead_code)]
    fn add_interoperability_fixtures(&mut self) {
        let fixtures = vec![FixtureSpec {
            id: "interop_standard_params".to_string(),
            name: "Standard Parameters".to_string(),
            category: FixtureCategory::Interoperability,
            description: "Common parameters for cross-implementation testing".to_string(),
            config: RoundTripConfig {
                source_symbols: 256,
                symbol_size: 1024,
                repair_symbols: 64,
                seed: 0x12345678,
                test_erasures: true,
                erasure_probability: 0.25,
            },
            expected_properties: FixtureProperties {
                should_succeed: true,
                expected_overhead_ratio: Some(0.25),
                max_encode_time_ms: Some(2000),
                max_decode_time_ms: Some(2000),
                memory_profile: MemoryProfile::Moderate,
                cross_compat: true,
            },
            priority: 2,
            expects_error: false,
            tags: vec!["interop".to_string(), "standard".to_string()],
        }];

        self.fixtures
            .insert(FixtureCategory::Interoperability, fixtures);
    }

    // Data generation methods for different fixture categories

    #[allow(dead_code)]

    fn generate_basic_data(&self, size: usize, seed: u64) -> Vec<u8> {
        let mut data = vec![0u8; size];
        let mut rng = seed;

        for byte in data.iter_mut() {
            rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (rng >> 24) as u8;
        }

        data
    }

    #[allow(dead_code)]

    fn generate_edge_case_data(&self, size: usize, fixture_id: &str) -> Vec<u8> {
        match fixture_id {
            "edge_minimal_symbols" => vec![0xAA],
            "edge_max_symbols" => {
                let mut data = vec![0u8; size];
                // Fill with alternating pattern
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte = (i % 256) as u8;
                }
                data
            }
            _ => vec![0x55; size],
        }
    }

    #[allow(dead_code)]

    fn generate_performance_data(&self, size: usize, seed: u64) -> Vec<u8> {
        // Generate data with realistic content patterns
        self.generate_basic_data(size, seed)
    }

    #[allow(dead_code)]

    fn generate_error_test_data(&self, size: usize, fixture_id: &str) -> Vec<u8> {
        match fixture_id {
            "error_high_erasure" => {
                // Generate data that's challenging for high erasure rates
                let mut data = vec![0u8; size];
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte = if i % 3 == 0 { 0xFF } else { 0x00 };
                }
                data
            }
            _ => vec![0; size],
        }
    }

    #[allow(dead_code)]

    fn generate_spec_test_data(&self, size: usize, seed: u64) -> Vec<u8> {
        // Generate data suitable for specification compliance testing
        self.generate_basic_data(size, seed)
    }

    #[allow(dead_code)]

    fn generate_interop_data(&self, size: usize, seed: u64) -> Vec<u8> {
        // Generate well-known test vectors for interoperability
        self.generate_basic_data(size, seed)
    }

    /// Returns all fixtures in a specific category
    #[allow(dead_code)]
    pub fn get_fixtures_by_category(&self, category: FixtureCategory) -> Option<&Vec<FixtureSpec>> {
        self.fixtures.get(&category)
    }

    /// Returns all fixture IDs matching given tags
    #[allow(dead_code)]
    pub fn get_fixtures_by_tags(&self, tags: &[String]) -> Vec<&FixtureSpec> {
        self.fixtures
            .values()
            .flatten()
            .filter(|fixture| tags.iter().any(|tag| fixture.tags.contains(tag)))
            .collect()
    }

    /// Returns high-priority fixtures for smoke testing
    #[allow(dead_code)]
    pub fn get_smoke_test_fixtures(&self) -> Vec<&FixtureSpec> {
        self.fixtures
            .values()
            .flatten()
            .filter(|fixture| fixture.priority <= 2)
            .collect()
    }
}

/// Complete fixture data with metadata
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct FixtureData {
    spec: FixtureSpec,
    input: RoundTripInput,
    metadata: FixtureMetadata,
}

/// Metadata about fixture generation
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct FixtureMetadata {
    generated_at: chrono::DateTime<chrono::Utc>,
    generator_version: String,
    rfc_6330_version: String,
}

/// Summary of fixture generation results
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct FixtureGenerationSummary {
    pub generated_fixtures: usize,
    pub failed_fixtures: usize,
    pub generated_files: Vec<PathBuf>,
    pub errors: Vec<String>,
}

#[allow(dead_code)]

impl FixtureGenerationSummary {
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        self.failed_fixtures == 0 && self.generated_fixtures > 0
    }
}

/// Errors that can occur during fixture generation
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum FixtureGenerationError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Data generation error: {0}")]
    DataGenerationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[allow(dead_code)]
    fn test_fixture_category_descriptions() {
        assert!(!FixtureCategory::BasicOperations.description().is_empty());
        assert!(!FixtureCategory::EdgeCases.rfc_sections().is_empty());
    }

    #[test]
    #[allow(dead_code)]
    fn test_memory_profile_serialization() {
        let profile = MemoryProfile::Linear;
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: MemoryProfile = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, MemoryProfile::Linear));
    }

    #[test]
    #[allow(dead_code)]
    fn test_fixture_generator_creation() {
        let temp_dir = TempDir::new().unwrap();
        let generator = FixtureGenerator::new(temp_dir.path());

        // Should have fixtures in all categories
        assert!(generator
            .fixtures
            .contains_key(&FixtureCategory::BasicOperations));
        assert!(generator.fixtures.contains_key(&FixtureCategory::EdgeCases));
    }

    #[test]
    #[allow(dead_code)]
    fn test_fixture_filtering() {
        let temp_dir = TempDir::new().unwrap();
        let generator = FixtureGenerator::new(temp_dir.path());

        let smoke_tests = generator.get_smoke_test_fixtures();
        assert!(!smoke_tests.is_empty());

        let basic_fixtures = generator.get_fixtures_by_tags(&["basic".to_string()]);
        assert!(!basic_fixtures.is_empty());
    }

    #[test]
    #[allow(dead_code)]
    fn test_data_generation_deterministic() {
        let temp_dir = TempDir::new().unwrap();
        let generator = FixtureGenerator::new(temp_dir.path());

        let data1 = generator.generate_basic_data(100, 42);
        let data2 = generator.generate_basic_data(100, 42);
        assert_eq!(data1, data2);

        let data3 = generator.generate_basic_data(100, 43);
        assert_ne!(data1, data3);
    }
}
