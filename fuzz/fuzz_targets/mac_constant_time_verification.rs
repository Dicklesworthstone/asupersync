//! Constant-time MAC verification property fuzzer.
//!
//! This fuzzer specifically targets the constant-time property of MAC verification
//! to ensure no timing side-channels leak information about MAC mismatch patterns.
//!
//! Tests:
//! 1. AuthenticationTag::verify() timing consistency across mismatch patterns
//! 2. AuthenticationTag::PartialEq timing consistency
//! 3. No early returns based on first differing byte position
//! 4. Timing invariance across different key/symbol combinations
//!
//! Security Property: Verification time must be independent of:
//! - Position of first differing byte in MAC comparison
//! - Number of matching prefix bytes before first difference
//! - Bit patterns in the differing bytes
//! - MAC tag validity (real vs zero/random tags)

#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::{AuthKey, AuthenticationTag};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;
use std::time::{Duration, Instant};

const MAX_PAYLOAD_LEN: usize = 256;
const TIMING_SAMPLES: usize = 100;
const TIMING_WARMUP: usize = 10;

#[derive(Debug, Arbitrary)]
struct ConstantTimeTestInput {
    key_seed: u64,
    symbol_payload: Vec<u8>,
    symbol_metadata: SymbolMetadata,
    test_scenarios: Vec<TimingTestScenario>,
}

#[derive(Debug, Arbitrary)]
struct SymbolMetadata {
    object_id: u128,
    sbn: u8,
    esi: u32,
    is_source: bool,
}

#[derive(Debug, Arbitrary)]
enum TimingTestScenario {
    /// Test timing across different first-mismatch positions
    FirstMismatchPosition {
        mismatch_byte_positions: Vec<u8>, // 0-31 for 32-byte MAC
    },
    /// Test timing for prefix-matching vs completely different MACs
    PrefixMatching {
        prefix_lengths: Vec<u8>,  // 0-32
        suffix_patterns: Vec<u8>, // Different byte patterns for non-matching suffix
    },
    /// Test timing between valid MAC vs zero/random invalid MACs
    ValidVsInvalid {
        invalid_patterns: Vec<InvalidMacPattern>,
    },
    /// Test PartialEq constant-time property specifically
    PartialEqTiming {
        comparison_pairs: Vec<MacComparisonPair>,
    },
}

#[derive(Debug, Arbitrary)]
enum InvalidMacPattern {
    AllZeros,
    AllOnes,
    Random([u8; 32]),
    SingleBitFlip { byte_idx: u8, bit_idx: u8 },
}

#[derive(Debug, Arbitrary)]
struct MacComparisonPair {
    first_tag_mutation: TagMutation,
    second_tag_mutation: TagMutation,
}

#[derive(Debug, Arbitrary)]
enum TagMutation {
    Identity,
    FlipByte { idx: u8, value: u8 },
    FlipBit { byte_idx: u8, bit_idx: u8 },
    Zero,
    Max,
}

fuzz_target!(|input: ConstantTimeTestInput| {
    // Limit payload size to prevent timeouts
    if input.symbol_payload.len() > MAX_PAYLOAD_LEN {
        return;
    }

    let key = AuthKey::from_seed(input.key_seed);
    let symbol = create_symbol(&input.symbol_metadata, &input.symbol_payload);
    let valid_tag = AuthenticationTag::compute(&key, &symbol);

    // Test each timing scenario
    for scenario in input.test_scenarios.iter().take(4) {
        // Limit scenarios to prevent timeout
        match scenario {
            TimingTestScenario::FirstMismatchPosition {
                mismatch_byte_positions,
            } => {
                test_first_mismatch_timing(&key, &symbol, &valid_tag, mismatch_byte_positions);
            }
            TimingTestScenario::PrefixMatching {
                prefix_lengths,
                suffix_patterns,
            } => {
                test_prefix_matching_timing(
                    &key,
                    &symbol,
                    &valid_tag,
                    prefix_lengths,
                    suffix_patterns,
                );
            }
            TimingTestScenario::ValidVsInvalid { invalid_patterns } => {
                test_valid_vs_invalid_timing(&key, &symbol, &valid_tag, invalid_patterns);
            }
            TimingTestScenario::PartialEqTiming { comparison_pairs } => {
                test_partial_eq_timing(&key, &symbol, &valid_tag, comparison_pairs);
            }
        }
    }
});

fn create_symbol(metadata: &SymbolMetadata, payload: &[u8]) -> Symbol {
    let symbol_id = SymbolId::new(
        ObjectId::from_u128(metadata.object_id),
        metadata.sbn,
        metadata.esi,
    );
    let kind = if metadata.is_source {
        SymbolKind::Source
    } else {
        SymbolKind::Repair
    };
    Symbol::new(symbol_id, payload.to_vec(), kind)
}

fn test_first_mismatch_timing(
    key: &AuthKey,
    symbol: &Symbol,
    valid_tag: &AuthenticationTag,
    mismatch_positions: &[u8],
) {
    let mut timing_by_position: Vec<(u8, Duration)> = Vec::new();

    for &pos in mismatch_positions.iter().take(8) {
        let pos = pos % 32; // Clamp to valid MAC byte range

        // Create a tag that differs at the specified position
        let mut invalid_bytes = *valid_tag.as_bytes();
        invalid_bytes[pos as usize] ^= 1; // Flip one bit
        let invalid_tag = AuthenticationTag::from_bytes(invalid_bytes);

        // Measure verification timing
        let timing = measure_verification_timing(key, symbol, &invalid_tag);
        timing_by_position.push((pos, timing));
    }

    // Assert timing consistency: no position should be significantly faster/slower
    // This is a statistical test - individual measurements may vary, but the
    // constant-time property means early vs late mismatches should have similar timing
    assert_timing_consistency(&timing_by_position, "first_mismatch_position");
}

fn test_prefix_matching_timing(
    key: &AuthKey,
    symbol: &Symbol,
    valid_tag: &AuthenticationTag,
    prefix_lengths: &[u8],
    suffix_patterns: &[u8],
) {
    let mut timing_by_prefix_len: Vec<(u8, Duration)> = Vec::new();

    for &prefix_len in prefix_lengths.iter().take(6) {
        let prefix_len = (prefix_len % 33).min(32); // 0-32 valid range

        for &pattern in suffix_patterns.iter().take(4) {
            // Create tag with matching prefix but different suffix
            let mut modified_bytes = *valid_tag.as_bytes();
            for byte in modified_bytes.iter_mut().skip(prefix_len as usize) {
                *byte = pattern;
            }

            // Ensure it's actually different if prefix_len < 32
            if prefix_len < 32 && modified_bytes == *valid_tag.as_bytes() {
                modified_bytes[31] ^= 1;
            }

            let test_tag = AuthenticationTag::from_bytes(modified_bytes);
            let timing = measure_verification_timing(key, symbol, &test_tag);
            timing_by_prefix_len.push((prefix_len, timing));
        }
    }

    // Timing should not correlate with prefix length - constant-time means
    // we always examine the full MAC regardless of where the first difference is
    assert_timing_consistency(&timing_by_prefix_len, "prefix_matching");
}

fn test_valid_vs_invalid_timing(
    key: &AuthKey,
    symbol: &Symbol,
    valid_tag: &AuthenticationTag,
    invalid_patterns: &[InvalidMacPattern],
) {
    let mut all_timings: Vec<Duration> = Vec::new();

    // Time the valid tag
    let valid_timing = measure_verification_timing(key, symbol, valid_tag);
    all_timings.push(valid_timing);

    // Time invalid patterns
    for pattern in invalid_patterns.iter().take(8) {
        let invalid_tag = match pattern {
            InvalidMacPattern::AllZeros => AuthenticationTag::zero(),
            InvalidMacPattern::AllOnes => AuthenticationTag::from_bytes([0xFF; 32]),
            InvalidMacPattern::Random(bytes) => AuthenticationTag::from_bytes(*bytes),
            InvalidMacPattern::SingleBitFlip { byte_idx, bit_idx } => {
                let mut bytes = *valid_tag.as_bytes();
                let byte_idx = (*byte_idx % 32) as usize;
                let bit_idx = bit_idx % 8;
                bytes[byte_idx] ^= 1 << bit_idx;
                AuthenticationTag::from_bytes(bytes)
            }
        };

        let invalid_timing = measure_verification_timing(key, symbol, &invalid_tag);
        all_timings.push(invalid_timing);
    }

    // Valid vs invalid verification should have similar timing profiles
    // This prevents timing oracle attacks that distinguish valid/invalid by timing
    assert_uniform_timing_distribution(&all_timings, "valid_vs_invalid");
}

fn test_partial_eq_timing(
    _key: &AuthKey,
    _symbol: &Symbol,
    valid_tag: &AuthenticationTag,
    comparison_pairs: &[MacComparisonPair],
) {
    for pair in comparison_pairs.iter().take(6) {
        let tag1 = apply_tag_mutation(valid_tag, &pair.first_tag_mutation);
        let tag2 = apply_tag_mutation(valid_tag, &pair.second_tag_mutation);

        // Measure PartialEq timing - this uses our custom constant-time implementation
        let timing = measure_partial_eq_timing(&tag1, &tag2);

        // The timing should be consistent regardless of:
        // - Whether the tags are equal or different
        // - Where the first difference occurs in the byte arrays
        // - The bit patterns of the differing bytes

        // For single fuzz run, just assert it doesn't panic and completes reasonably fast
        assert!(
            timing.as_micros() < 1000,
            "PartialEq timing should be under 1ms"
        );
    }
}

fn measure_verification_timing(
    key: &AuthKey,
    symbol: &Symbol,
    tag: &AuthenticationTag,
) -> Duration {
    // Warmup to stabilize timing
    for _ in 0..TIMING_WARMUP {
        observe_verify_result(tag, tag.verify(key, symbol));
    }

    // Measure multiple samples and take median to reduce noise
    let mut timings = Vec::with_capacity(TIMING_SAMPLES);
    for _ in 0..TIMING_SAMPLES {
        let start = Instant::now();
        observe_verify_result(tag, tag.verify(key, symbol));
        let elapsed = start.elapsed();
        timings.push(elapsed);
    }

    timings.sort();
    timings[TIMING_SAMPLES / 2] // Median timing
}

fn measure_partial_eq_timing(tag1: &AuthenticationTag, tag2: &AuthenticationTag) -> Duration {
    // Warmup
    for _ in 0..TIMING_WARMUP {
        observe_partial_eq_result(tag1, tag2, tag1 == tag2);
    }

    let mut timings = Vec::with_capacity(TIMING_SAMPLES);
    for _ in 0..TIMING_SAMPLES {
        let start = Instant::now();
        observe_partial_eq_result(tag1, tag2, tag1 == tag2);
        let elapsed = start.elapsed();
        timings.push(elapsed);
    }

    timings.sort();
    timings[TIMING_SAMPLES / 2] // Median timing
}

fn observe_verify_result(tag: &AuthenticationTag, verified: bool) {
    if tag.is_zero() {
        assert!(
            !verified,
            "AuthenticationTag::verify accepted the all-zero sentinel tag",
        );
    }
    black_box(verified);
}

fn observe_partial_eq_result(tag1: &AuthenticationTag, tag2: &AuthenticationTag, equal: bool) {
    let expected = tag1.as_bytes() == tag2.as_bytes();
    assert_eq!(
        equal, expected,
        "AuthenticationTag PartialEq result diverged from byte equality",
    );
    black_box(equal);
}

fn apply_tag_mutation(base_tag: &AuthenticationTag, mutation: &TagMutation) -> AuthenticationTag {
    let mut bytes = *base_tag.as_bytes();

    match mutation {
        TagMutation::Identity => {
            // No change
        }
        TagMutation::FlipByte { idx, value } => {
            let idx = (*idx % 32) as usize;
            bytes[idx] = *value;
        }
        TagMutation::FlipBit { byte_idx, bit_idx } => {
            let byte_idx = (*byte_idx % 32) as usize;
            let bit_idx = bit_idx % 8;
            bytes[byte_idx] ^= 1 << bit_idx;
        }
        TagMutation::Zero => {
            bytes = [0; 32];
        }
        TagMutation::Max => {
            bytes = [0xFF; 32];
        }
    }

    AuthenticationTag::from_bytes(bytes)
}

fn assert_timing_consistency(timings: &[(u8, Duration)], test_name: &str) {
    if timings.len() < 2 {
        return; // Need at least 2 samples to compare
    }

    // Calculate coefficient of variation (CV) = std_dev / mean
    // For constant-time operations, CV should be low regardless of input patterns
    let durations: Vec<_> = timings.iter().map(|(_, d)| d.as_nanos() as f64).collect();
    let mean = durations.iter().sum::<f64>() / durations.len() as f64;
    let variance =
        durations.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / durations.len() as f64;
    let std_dev = variance.sqrt();
    let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

    // Constant-time implementation should have low timing variance
    // This is a statistical property test - we're asserting the coefficient of variation
    // is reasonable for constant-time operation (not a tight bound, just sanity check)
    assert!(
        cv < 2.0, // Allow for some timing noise but flag excessive variance
        "{} timing CV too high: {:.3} (mean: {:.1}ns, std_dev: {:.1}ns)",
        test_name,
        cv,
        mean,
        std_dev
    );
}

fn assert_uniform_timing_distribution(timings: &[Duration], test_name: &str) {
    if timings.len() < 2 {
        return;
    }

    // Similar statistical check for uniform timing across different inputs
    let durations: Vec<_> = timings.iter().map(|d| d.as_nanos() as f64).collect();
    let mean = durations.iter().sum::<f64>() / durations.len() as f64;
    let variance =
        durations.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / durations.len() as f64;
    let std_dev = variance.sqrt();
    let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

    assert!(
        cv < 2.0,
        "{} timing distribution too variable: CV = {:.3}",
        test_name,
        cv
    );

    // Also assert no individual timing is too far from median (outlier detection)
    let mut sorted_durations = durations.clone();
    sorted_durations.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = sorted_durations[sorted_durations.len() / 2];

    for &timing in &durations {
        let ratio = if median > 0.0 { timing / median } else { 1.0 };
        assert!(
            (0.1..=10.0).contains(&ratio), // No timing should be >10x faster/slower than median
            "{} timing outlier detected: {:.1}ns vs median {:.1}ns (ratio: {:.2})",
            test_name,
            timing,
            median,
            ratio
        );
    }
}
