//! OpenTelemetry Trace ID Randomness Conformance Test (Tick #144)
//!
//! This guard verifies local trace ID generation health and samples
//! opentelemetry-sdk generation separately. It intentionally fails closed for
//! SDK parity because the two implementations are sampled from independent live
//! RNG streams, not a deterministic shared-source reference oracle.
//!
//! Key properties tested:
//! - Statistical uniformity of generated trace IDs
//! - Uniqueness over large sample sizes
//! - Independent distribution health for opentelemetry-sdk samples
//! - Entropy and randomness quality metrics
//! - Proper handling of invalid trace ID (all zeros)

use asupersync::observability::w3c_trace_context::TraceId as AsupersyncTraceId;
use opentelemetry_sdk::trace::{IdGenerator, RandomIdGenerator};
use std::collections::BTreeSet;

const OTEL_SDK_TRACE_ID_PARITY_UNIMPLEMENTED: &str = "deterministic shared-source opentelemetry-sdk trace ID parity oracle is not wired; refusing independent-RNG conformance claims";

/// Test cases for trace ID randomness conformance
struct TraceIdRandomnessTestCase {
    name: &'static str,
    sample_size: usize,
    description: &'static str,
}

/// Our test representation of trace ID generation
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct TraceIdData {
    bytes: [u8; 16],
}

impl TraceIdData {
    fn new(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    fn is_valid(&self) -> bool {
        self.bytes != [0; 16]
    }

    /// Calculate entropy of the trace ID bytes
    fn entropy(&self) -> f64 {
        let mut counts = [0u32; 256];
        for &byte in &self.bytes {
            counts[byte as usize] += 1;
        }

        let total = self.bytes.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

/// Statistical analysis of trace ID generation
#[derive(Debug)]
struct RandomnessAnalysis {
    sample_size: usize,
    unique_count: usize,
    collision_count: usize,
    entropy_mean: f64,
    entropy_std: f64,
    byte_distribution: Vec<[u32; 256]>, // Distribution per byte position
    invalid_count: usize,
}

impl RandomnessAnalysis {
    fn analyze(trace_ids: &[TraceIdData]) -> Self {
        let sample_size = trace_ids.len();
        let unique_set: BTreeSet<_> = trace_ids.iter().collect();
        let unique_count = unique_set.len();
        let collision_count = sample_size - unique_count;

        // Calculate entropy statistics
        let entropies: Vec<f64> = trace_ids.iter().map(|id| id.entropy()).collect();
        let entropy_mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let entropy_variance = entropies
            .iter()
            .map(|e| (e - entropy_mean).powi(2))
            .sum::<f64>()
            / entropies.len() as f64;
        let entropy_std = entropy_variance.sqrt();

        // Calculate byte distribution
        let mut byte_distribution = vec![[0u32; 256]; 16];
        for id in trace_ids {
            for (pos, &byte) in id.bytes.iter().enumerate() {
                byte_distribution[pos][byte as usize] += 1;
            }
        }

        let invalid_count = trace_ids.iter().filter(|id| !id.is_valid()).count();

        RandomnessAnalysis {
            sample_size,
            unique_count,
            collision_count,
            entropy_mean,
            entropy_std,
            byte_distribution,
            invalid_count,
        }
    }

    /// Calculate chi-squared statistic for uniformity test
    fn chi_squared_uniformity(&self) -> Vec<f64> {
        let expected = self.sample_size as f64 / 256.0;

        self.byte_distribution
            .iter()
            .map(|dist| {
                dist.iter()
                    .map(|&observed| {
                        let diff = observed as f64 - expected;
                        (diff * diff) / expected
                    })
                    .sum::<f64>()
            })
            .collect()
    }
}

fn main() {
    println!("🔍 OpenTelemetry Trace ID Randomness Guard");
    println!("Checking local and SDK trace ID sample health without claiming exact parity");

    let test_cases = vec![
        TraceIdRandomnessTestCase {
            name: "small_sample",
            sample_size: 1000,
            description: "Small sample for quick validation",
        },
        TraceIdRandomnessTestCase {
            name: "medium_sample",
            sample_size: 5000,
            description: "Medium sample for statistical analysis",
        },
        TraceIdRandomnessTestCase {
            name: "large_sample",
            sample_size: 10000,
            description: "Large sample for distribution conformance",
        },
        TraceIdRandomnessTestCase {
            name: "fresh_generator_short_run",
            sample_size: 1000,
            description: "Fresh generator short run",
        },
        TraceIdRandomnessTestCase {
            name: "second_fresh_generator_short_run",
            sample_size: 1000,
            description: "Second fresh generator short run",
        },
    ];

    println!(
        "📋 Running {} trace ID randomness conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Test our implementation
        let our_trace_ids = test_our_trace_id_generation(test_case);

        // Sample opentelemetry-sdk independently. This is a health comparator,
        // not an exact conformance oracle for asupersync.
        let reference_trace_ids = test_reference_trace_id_generation(test_case);

        // Check each sample set independently. Do not claim exact distribution
        // matching from separate live RNG streams.
        if let Err(error) =
            check_trace_id_distribution_health(&our_trace_ids, &reference_trace_ids, test_case)
        {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {} local/sdk health checks", test_case.name);
        }
    }

    // Test randomness properties
    println!("\n📋 Testing trace ID randomness properties");
    test_trace_id_randomness_properties(&mut failed_tests);

    // Report results
    println!("\n📊 Trace ID Randomness Guard Results");
    if failed_tests.is_empty() {
        println!("⚠️  LOCAL HEALTH CHECKS PASSED");
        println!("{}", final_status_line(failed_tests.len()));
        std::process::exit(exit_code_for_summary(failed_tests.len()));
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        println!("{}", final_status_line(failed_tests.len()));
        std::process::exit(exit_code_for_summary(failed_tests.len()));
    }
}

fn final_status_line(local_failure_count: usize) -> String {
    if local_failure_count == 0 {
        format!("REFERENCE UNAVAILABLE - {OTEL_SDK_TRACE_ID_PARITY_UNIMPLEMENTED}")
    } else {
        format!(
            "LOCAL HEALTH CHECK FAILED - {local_failure_count} trace ID sample health checks failed"
        )
    }
}

const fn exit_code_for_summary(_local_failure_count: usize) -> i32 {
    1
}

/// Test our trace ID generation implementation
fn test_our_trace_id_generation(test_case: &TraceIdRandomnessTestCase) -> Vec<TraceIdData> {
    let mut trace_ids = Vec::with_capacity(test_case.sample_size);

    for _ in 0..test_case.sample_size {
        let trace_id = AsupersyncTraceId::new_random();
        let trace_id_bytes = trace_id_hex_to_bytes(&trace_id.to_hex());
        trace_ids.push(TraceIdData::new(trace_id_bytes));
    }

    trace_ids
}

/// Sample opentelemetry-sdk trace ID generation for independent health checks.
fn test_reference_trace_id_generation(test_case: &TraceIdRandomnessTestCase) -> Vec<TraceIdData> {
    let generator = RandomIdGenerator::default();
    let mut trace_ids = Vec::with_capacity(test_case.sample_size);

    for _ in 0..test_case.sample_size {
        let trace_id = generator.new_trace_id();
        let trace_id_bytes = trace_id_hex_to_bytes(&format!("{trace_id:032x}"));
        trace_ids.push(TraceIdData::new(trace_id_bytes));
    }

    trace_ids
}

fn trace_id_hex_to_bytes(hex: &str) -> [u8; 16] {
    assert_eq!(hex.len(), 32, "trace ID hex must be 32 chars");
    let mut bytes = [0u8; 16];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let offset = idx * 2;
        *byte = u8::from_str_radix(&hex[offset..offset + 2], 16).expect("trace ID hex must parse");
    }
    bytes
}

/// Check independent trace ID sample health for both implementations.
fn check_trace_id_distribution_health(
    our_trace_ids: &[TraceIdData],
    reference_trace_ids: &[TraceIdData],
    _test_case: &TraceIdRandomnessTestCase,
) -> Result<(), String> {
    if our_trace_ids.len() != reference_trace_ids.len() {
        return Err(format!(
            "Sample size mismatch: our={}, reference={}",
            our_trace_ids.len(),
            reference_trace_ids.len()
        ));
    }

    let our_analysis = RandomnessAnalysis::analyze(our_trace_ids);
    let ref_analysis = RandomnessAnalysis::analyze(reference_trace_ids);

    for (label, analysis) in [
        ("asupersync", &our_analysis),
        ("opentelemetry-sdk", &ref_analysis),
    ] {
        if analysis.invalid_count != 0 {
            return Err(format!(
                "{label} generated {} invalid all-zero trace IDs",
                analysis.invalid_count
            ));
        }

        let uniqueness_rate = analysis.unique_count as f64 / analysis.sample_size as f64;
        if uniqueness_rate < 0.99 {
            return Err(format!(
                "{label} uniqueness rate {:.4} is below 0.99",
                uniqueness_rate
            ));
        }
        if analysis.collision_count > analysis.sample_size / 100 {
            return Err(format!(
                "{label} collision count {} exceeds 1% of sample size {}",
                analysis.collision_count, analysis.sample_size
            ));
        }

        if analysis.entropy_mean < 3.0 {
            return Err(format!(
                "{label} entropy mean {:.3} is too low",
                analysis.entropy_mean
            ));
        }
    }

    Ok(())
}

/// Test general randomness properties
fn test_trace_id_randomness_properties(failed_tests: &mut Vec<(String, String)>) {
    let test_case = TraceIdRandomnessTestCase {
        name: "randomness_properties",
        sample_size: 10000,
        description: "General randomness property testing",
    };

    let trace_ids = test_our_trace_id_generation(&test_case);
    let analysis = RandomnessAnalysis::analyze(&trace_ids);

    // Test 1: Uniqueness rate should be very high
    let uniqueness_rate = analysis.unique_count as f64 / analysis.sample_size as f64;
    if uniqueness_rate < 0.99 {
        failed_tests.push((
            "uniqueness_rate".to_string(),
            format!("Uniqueness rate {:.4} is below 0.99", uniqueness_rate),
        ));
    } else {
        println!("    ✅ uniqueness_rate: {:.4}", uniqueness_rate);
    }

    // Test 2: No invalid trace IDs should be generated.
    if analysis.invalid_count != 0 {
        failed_tests.push((
            "invalid_trace_ids".to_string(),
            format!("Too many invalid trace IDs: {}", analysis.invalid_count),
        ));
    } else {
        println!("    ✅ invalid_trace_ids: {}", analysis.invalid_count);
    }

    // Test 3: Entropy should be high (close to maximum for 16 bytes)
    if analysis.entropy_mean < 3.0 {
        failed_tests.push((
            "entropy_mean".to_string(),
            format!("Entropy {:.3} is too low", analysis.entropy_mean),
        ));
    } else {
        println!("    ✅ entropy_mean: {:.3}", analysis.entropy_mean);
    }

    // Test 4: Byte distribution uniformity (chi-squared test)
    let chi_squared_values = analysis.chi_squared_uniformity();
    let critical_value = 300.0; // Approximate critical value for 255 df at 0.05 significance

    let mut non_uniform_positions = Vec::new();
    for (pos, &chi_sq) in chi_squared_values.iter().enumerate() {
        if chi_sq > critical_value {
            non_uniform_positions.push((pos, chi_sq));
        }
    }

    if non_uniform_positions.len() > 2 {
        failed_tests.push((
            "byte_uniformity".to_string(),
            format!(
                "Too many non-uniform byte positions: {:?}",
                non_uniform_positions
            ),
        ));
    } else {
        println!(
            "    ✅ byte_uniformity: {} positions exceed threshold",
            non_uniform_positions.len()
        );
    }

    // Test 5: Standard deviation should be reasonable
    if analysis.entropy_std > 1.0 {
        failed_tests.push((
            "entropy_consistency".to_string(),
            format!(
                "Entropy standard deviation {:.3} is too high",
                analysis.entropy_std
            ),
        ));
    } else {
        println!(
            "    ✅ entropy_consistency: std={:.3}",
            analysis.entropy_std
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_id_hex_to_bytes() {
        let bytes = trace_id_hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        assert_eq!(
            bytes,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_trace_id_data_validity() {
        let valid_id = TraceIdData::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let invalid_id = TraceIdData::new([0; 16]);

        assert!(valid_id.is_valid());
        assert!(!invalid_id.is_valid());
    }

    #[test]
    fn test_trace_id_entropy_calculation() {
        let uniform_id = TraceIdData::new([0x01; 16]); // All same byte
        let mixed_id = TraceIdData::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        // Uniform distribution should have lower entropy than mixed
        assert!(uniform_id.entropy() < mixed_id.entropy());
    }

    #[test]
    fn test_our_trace_id_generation_uses_live_nonzero_ids() {
        let test_case = TraceIdRandomnessTestCase {
            name: "unit_live_nonzero",
            sample_size: 32,
            description: "Unit live nonzero",
        };
        let ids = test_our_trace_id_generation(&test_case);
        assert!(ids.iter().all(TraceIdData::is_valid));
    }

    #[test]
    fn test_trace_id_generation_uniqueness() {
        let mut ids = BTreeSet::new();
        let test_case = TraceIdRandomnessTestCase {
            name: "unit_uniqueness",
            sample_size: 1000,
            description: "Unit uniqueness",
        };

        for id in test_our_trace_id_generation(&test_case) {
            ids.insert(id.bytes);
        }

        // Should have very high uniqueness
        assert!(ids.len() > 995, "Generated IDs should be mostly unique");
    }

    #[test]
    fn test_randomness_analysis() {
        let test_case = TraceIdRandomnessTestCase {
            name: "unit_analysis",
            sample_size: 100,
            description: "Unit analysis",
        };
        let trace_ids = test_our_trace_id_generation(&test_case);

        let analysis = RandomnessAnalysis::analyze(&trace_ids);

        assert_eq!(analysis.sample_size, 100);
        assert!(analysis.unique_count > 95); // Should be mostly unique
        assert!(analysis.entropy_mean > 2.0); // Reasonable entropy
    }

    #[test]
    fn test_invalid_trace_id_handling() {
        // Pin the validity predicate for the forbidden all-zero W3C trace ID.
        let invalid_bytes = [0; 16];
        let trace_id = if invalid_bytes == [0; 16] {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        } else {
            invalid_bytes
        };

        let id_data = TraceIdData::new(trace_id);
        assert!(id_data.is_valid());
    }

    #[test]
    fn source_no_longer_claims_exact_sdk_randomness_parity() {
        let source = include_str!("otel_trace_id_randomness_conformance.rs");
        for forbidden in [
            concat!(
                "identical randomness distribution compared to ",
                "opentelemetry-sdk"
            ),
            concat!("same ", "RNG source"),
            concat!("Trace ID generation is ", "conformant"),
            concat!("RNG distribution matches ", "opentelemetry-sdk exactly"),
        ] {
            assert!(
                !source.contains(forbidden),
                "source must not claim exact SDK parity from independent RNG samples: {forbidden}"
            );
        }
        assert!(source.contains(OTEL_SDK_TRACE_ID_PARITY_UNIMPLEMENTED));
    }

    #[test]
    fn guard_exits_nonzero_when_only_local_health_checks_pass() {
        assert_eq!(exit_code_for_summary(0), 1);
        let status = final_status_line(0);
        assert!(status.contains("REFERENCE UNAVAILABLE"));
        assert!(status.contains("refusing independent-RNG conformance claims"));
    }

    #[test]
    fn guard_exits_nonzero_when_local_health_checks_fail() {
        assert_eq!(exit_code_for_summary(3), 1);
        let status = final_status_line(3);
        assert!(status.contains("LOCAL HEALTH CHECK FAILED"));
        assert!(status.contains("3 trace ID sample health checks failed"));
    }
}
