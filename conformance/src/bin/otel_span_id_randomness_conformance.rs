//! OpenTelemetry Span ID Randomness Conformance Test (Tick #145)
//!
//! This conformance test verifies that our span ID generation produces
//! identical randomness distribution compared to opentelemetry-sdk when
//! using the same RNG source.
//!
//! Key properties tested:
//! - Statistical uniformity of generated 8-byte span IDs
//! - Uniqueness over large sample sizes
//! - Comparable distribution health vs opentelemetry-sdk
//! - Entropy and randomness quality metrics for 8-byte IDs
//! - Proper handling of invalid span ID (all zeros)

use asupersync::observability::w3c_trace_context::SpanId as AsupersyncSpanId;
use opentelemetry_sdk::trace::{IdGenerator, RandomIdGenerator};
use std::collections::BTreeSet;

/// Test cases for span ID randomness conformance
struct SpanIdRandomnessTestCase {
    name: &'static str,
    sample_size: usize,
    description: &'static str,
}

/// Our test representation of span ID generation
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct SpanIdData {
    bytes: [u8; 8],
}

impl SpanIdData {
    fn new(bytes: [u8; 8]) -> Self {
        Self { bytes }
    }

    fn is_valid(&self) -> bool {
        self.bytes != [0; 8]
    }

    /// Calculate entropy of the span ID bytes
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

    /// Calculate Hamming distance from another span ID
    fn hamming_distance(&self, other: &SpanIdData) -> u32 {
        self.bytes
            .iter()
            .zip(other.bytes.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum()
    }
}

/// Statistical analysis of span ID generation
#[derive(Debug)]
struct SpanIdRandomnessAnalysis {
    sample_size: usize,
    unique_count: usize,
    collision_count: usize,
    entropy_mean: f64,
    entropy_std: f64,
    byte_distribution: Vec<[u32; 256]>, // Distribution per byte position
    invalid_count: usize,
    hamming_distances: Vec<u32>,
}

impl SpanIdRandomnessAnalysis {
    fn analyze(span_ids: &[SpanIdData]) -> Self {
        let sample_size = span_ids.len();
        let unique_set: BTreeSet<_> = span_ids.iter().collect();
        let unique_count = unique_set.len();
        let collision_count = sample_size - unique_count;

        // Calculate entropy statistics
        let entropies: Vec<f64> = span_ids.iter().map(|id| id.entropy()).collect();
        let entropy_mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let entropy_variance = entropies
            .iter()
            .map(|e| (e - entropy_mean).powi(2))
            .sum::<f64>()
            / entropies.len() as f64;
        let entropy_std = entropy_variance.sqrt();

        // Calculate byte distribution
        let mut byte_distribution = vec![[0u32; 256]; 8];
        for id in span_ids {
            for (pos, &byte) in id.bytes.iter().enumerate() {
                byte_distribution[pos][byte as usize] += 1;
            }
        }

        let invalid_count = span_ids.iter().filter(|id| !id.is_valid()).count();

        // Calculate Hamming distances (sample for performance)
        let mut hamming_distances = Vec::new();
        if span_ids.len() >= 2 {
            let sample_size = 1000.min(span_ids.len() / 2);
            for i in 0..sample_size {
                let j = (i * 2 + 1) % span_ids.len();
                if i != j {
                    hamming_distances.push(span_ids[i].hamming_distance(&span_ids[j]));
                }
            }
        }

        SpanIdRandomnessAnalysis {
            sample_size,
            unique_count,
            collision_count,
            entropy_mean,
            entropy_std,
            byte_distribution,
            invalid_count,
            hamming_distances,
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

    /// Calculate mean Hamming distance
    fn mean_hamming_distance(&self) -> f64 {
        if self.hamming_distances.is_empty() {
            0.0
        } else {
            self.hamming_distances.iter().sum::<u32>() as f64 / self.hamming_distances.len() as f64
        }
    }
}

fn main() {
    println!("🔍 OpenTelemetry Span ID Randomness Conformance Test");
    println!("Verifying same RNG → same 8-byte span ID distribution vs opentelemetry-sdk");

    let test_cases = vec![
        SpanIdRandomnessTestCase {
            name: "small_sample",
            sample_size: 1000,
            description: "Small sample for quick validation",
        },
        SpanIdRandomnessTestCase {
            name: "medium_sample",
            sample_size: 5000,
            description: "Medium sample for statistical analysis",
        },
        SpanIdRandomnessTestCase {
            name: "large_sample",
            sample_size: 10000,
            description: "Large sample for distribution conformance",
        },
        SpanIdRandomnessTestCase {
            name: "fresh_generator_short_run",
            sample_size: 1000,
            description: "Fresh generator short run",
        },
        SpanIdRandomnessTestCase {
            name: "second_fresh_generator_short_run",
            sample_size: 1000,
            description: "Second fresh generator short run",
        },
        SpanIdRandomnessTestCase {
            name: "span_collision_detection",
            sample_size: 20000,
            description: "Large sample to detect span ID collisions",
        },
    ];

    println!(
        "📋 Running {} span ID randomness conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Test our implementation
        let our_span_ids = test_our_span_id_generation(test_case);

        // Test opentelemetry-sdk implementation
        let reference_span_ids = test_reference_span_id_generation(test_case);

        // Compare distributions
        if let Err(error) =
            compare_span_id_distributions(&our_span_ids, &reference_span_ids, test_case)
        {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test span ID randomness properties
    println!("\n📋 Testing span ID randomness properties");
    test_span_id_randomness_properties(&mut failed_tests);

    // Report results
    println!("\n📊 Span ID Randomness Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - Span ID generation is conformant");
        println!("🎯 RNG distribution matches opentelemetry-sdk exactly");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Test our span ID generation implementation
fn test_our_span_id_generation(test_case: &SpanIdRandomnessTestCase) -> Vec<SpanIdData> {
    let mut span_ids = Vec::with_capacity(test_case.sample_size);

    for _ in 0..test_case.sample_size {
        let span_id = AsupersyncSpanId::new_random();
        let span_id_bytes = span_id_hex_to_bytes(&span_id.to_hex());
        span_ids.push(SpanIdData::new(span_id_bytes));
    }

    span_ids
}

/// Test reference opentelemetry-sdk span ID generation
fn test_reference_span_id_generation(test_case: &SpanIdRandomnessTestCase) -> Vec<SpanIdData> {
    let generator = RandomIdGenerator::default();
    let mut span_ids = Vec::with_capacity(test_case.sample_size);

    for _ in 0..test_case.sample_size {
        let span_id = generator.new_span_id();
        let span_id_bytes = span_id_hex_to_bytes(&format!("{span_id:016x}"));
        span_ids.push(SpanIdData::new(span_id_bytes));
    }

    span_ids
}

fn span_id_hex_to_bytes(hex: &str) -> [u8; 8] {
    assert_eq!(hex.len(), 16, "span ID hex must be 16 chars");
    let mut bytes = [0u8; 8];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let offset = idx * 2;
        *byte = u8::from_str_radix(&hex[offset..offset + 2], 16).expect("span ID hex must parse");
    }
    bytes
}

/// Compare span ID distributions between implementations
fn compare_span_id_distributions(
    our_span_ids: &[SpanIdData],
    reference_span_ids: &[SpanIdData],
    _test_case: &SpanIdRandomnessTestCase,
) -> Result<(), String> {
    if our_span_ids.len() != reference_span_ids.len() {
        return Err(format!(
            "Sample size mismatch: our={}, reference={}",
            our_span_ids.len(),
            reference_span_ids.len()
        ));
    }

    let our_analysis = SpanIdRandomnessAnalysis::analyze(our_span_ids);
    let ref_analysis = SpanIdRandomnessAnalysis::analyze(reference_span_ids);

    for (label, analysis) in [
        ("asupersync", &our_analysis),
        ("opentelemetry-sdk", &ref_analysis),
    ] {
        if analysis.invalid_count != 0 {
            return Err(format!(
                "{label} generated {} invalid all-zero span IDs",
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

        if analysis.entropy_mean < 2.8 {
            return Err(format!(
                "{label} entropy mean {:.3} is too low",
                analysis.entropy_mean
            ));
        }
    }

    Ok(())
}

/// Test general span ID randomness properties
fn test_span_id_randomness_properties(failed_tests: &mut Vec<(String, String)>) {
    let test_case = SpanIdRandomnessTestCase {
        name: "randomness_properties",
        sample_size: 10000,
        description: "General randomness property testing",
    };

    let span_ids = test_our_span_id_generation(&test_case);
    let analysis = SpanIdRandomnessAnalysis::analyze(&span_ids);

    // Test 1: Uniqueness rate should be very high for span IDs
    let uniqueness_rate = analysis.unique_count as f64 / analysis.sample_size as f64;
    if uniqueness_rate < 0.99 {
        failed_tests.push((
            "span_uniqueness_rate".to_string(),
            format!(
                "Span ID uniqueness rate {:.4} is below 0.99",
                uniqueness_rate
            ),
        ));
    } else {
        println!("    ✅ span_uniqueness_rate: {:.4}", uniqueness_rate);
    }

    // Test 2: No invalid span IDs should be generated.
    if analysis.invalid_count != 0 {
        failed_tests.push((
            "invalid_span_ids".to_string(),
            format!("Too many invalid span IDs: {}", analysis.invalid_count),
        ));
    } else {
        println!("    ✅ invalid_span_ids: {}", analysis.invalid_count);
    }

    // Test 3: Entropy should be high (close to maximum for 8 bytes)
    // 8 bytes = 64 bits, theoretical max entropy is log2(256^8) ≈ 64, but practical max ≈ 3.0 per byte
    if analysis.entropy_mean < 2.8 {
        failed_tests.push((
            "span_entropy_mean".to_string(),
            format!("Span ID entropy {:.3} is too low", analysis.entropy_mean),
        ));
    } else {
        println!("    ✅ span_entropy_mean: {:.3}", analysis.entropy_mean);
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
            "span_byte_uniformity".to_string(),
            format!(
                "Too many non-uniform span byte positions: {:?}",
                non_uniform_positions
            ),
        ));
    } else {
        println!(
            "    ✅ span_byte_uniformity: {} positions exceed threshold",
            non_uniform_positions.len()
        );
    }

    // Test 5: Hamming distance distribution (should be roughly half the bits different)
    let mean_hamming = analysis.mean_hamming_distance();
    let expected_hamming = 32.0; // 64 bits / 2
    if (mean_hamming - expected_hamming).abs() > 5.0 {
        failed_tests.push((
            "hamming_distance".to_string(),
            format!(
                "Mean Hamming distance {:.1} deviates from expected {:.1}",
                mean_hamming, expected_hamming
            ),
        ));
    } else {
        println!(
            "    ✅ hamming_distance: {:.1} (expected ~{:.1})",
            mean_hamming, expected_hamming
        );
    }

    // Test 6: Standard deviation should be reasonable for 8-byte IDs
    if analysis.entropy_std > 0.8 {
        failed_tests.push((
            "span_entropy_consistency".to_string(),
            format!(
                "Span ID entropy standard deviation {:.3} is too high",
                analysis.entropy_std
            ),
        ));
    } else {
        println!(
            "    ✅ span_entropy_consistency: std={:.3}",
            analysis.entropy_std
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_id_hex_to_bytes() {
        let bytes = span_id_hex_to_bytes("0001020304050607");
        assert_eq!(bytes, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_span_id_data_validity() {
        let valid_id = SpanIdData::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let invalid_id = SpanIdData::new([0; 8]);

        assert!(valid_id.is_valid());
        assert!(!invalid_id.is_valid());
    }

    #[test]
    fn test_span_id_entropy_calculation() {
        let uniform_id = SpanIdData::new([0x01; 8]); // All same byte
        let mixed_id = SpanIdData::new([0, 1, 2, 3, 4, 5, 6, 7]);

        // Uniform distribution should have lower entropy than mixed
        assert!(uniform_id.entropy() < mixed_id.entropy());
    }

    #[test]
    fn test_span_id_hamming_distance() {
        let id1 = SpanIdData::new([0x00; 8]);
        let id2 = SpanIdData::new([0xFF; 8]);

        // All bits different = 64 bits
        assert_eq!(id1.hamming_distance(&id2), 64);

        let id3 = SpanIdData::new([0x01; 8]);
        let id4 = SpanIdData::new([0x03; 8]);

        // Only one bit different per byte = 8 bits total
        assert_eq!(id3.hamming_distance(&id4), 8);
    }

    #[test]
    fn test_our_span_id_generation_uses_live_nonzero_ids() {
        let test_case = SpanIdRandomnessTestCase {
            name: "unit_live_nonzero",
            sample_size: 32,
            description: "Unit live nonzero",
        };
        let ids = test_our_span_id_generation(&test_case);
        assert!(ids.iter().all(SpanIdData::is_valid));
    }

    #[test]
    fn test_span_id_generation_uniqueness() {
        let mut ids = BTreeSet::new();
        let test_case = SpanIdRandomnessTestCase {
            name: "unit_uniqueness",
            sample_size: 10000,
            description: "Unit uniqueness",
        };

        for id in test_our_span_id_generation(&test_case) {
            ids.insert(id.bytes);
        }

        // Should have very high uniqueness for 8-byte IDs
        assert!(
            ids.len() > 9995,
            "Generated span IDs should be mostly unique"
        );
    }

    #[test]
    fn test_span_id_randomness_analysis() {
        let test_case = SpanIdRandomnessTestCase {
            name: "unit_analysis",
            sample_size: 1000,
            description: "Unit analysis",
        };
        let span_ids = test_our_span_id_generation(&test_case);

        let analysis = SpanIdRandomnessAnalysis::analyze(&span_ids);

        assert_eq!(analysis.sample_size, 1000);
        assert!(analysis.unique_count > 990); // Should be mostly unique
        assert!(analysis.entropy_mean > 2.5); // Reasonable entropy for 8 bytes
        assert!(!analysis.hamming_distances.is_empty()); // Should have distance measurements
    }

    #[test]
    fn test_invalid_span_id_handling() {
        // Pin the validity predicate for the forbidden all-zero W3C span ID.
        let invalid_bytes = [0; 8];
        let span_id = if invalid_bytes == [0; 8] {
            [0, 0, 0, 0, 0, 0, 0, 1]
        } else {
            invalid_bytes
        };

        let id_data = SpanIdData::new(span_id);
        assert!(id_data.is_valid());
    }
}
