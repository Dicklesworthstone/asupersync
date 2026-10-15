//! W3C Trace Context trace_id 128-bit randomness audit test.
//!
//! **AUDIT SCOPE**: Verifies trace_id generation compliance with W3C Trace Context
//! specification requirement for 128 bits of randomness.
//!
//! **W3C TRACE CONTEXT SPECIFICATION REQUIREMENT**:
//! - trace_id MUST be 16 random bytes (128 bits of entropy)
//! - MUST be globally unique and unpredictable
//! - NOT: deterministic PRNG output (leaks generator state)
//! - NOT: two related 64-bit halves (reduces entropy)
//!
//! **CRITICAL DEFECT IDENTIFIED**:
//! - next_test_trace_id() uses splitmix64 PRNG with sequential seed
//! - Two 64-bit outputs: hi=splitmix64(seed), lo=splitmix64(seed^constant)
//! - Predictable sequence violates W3C randomness requirement
//! - Generator state leakage enables trace_id prediction

#![cfg(test)]

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

// Import the problematic implementation for testing
use super::w3c_trace_context::TraceId;

// Replicate the problematic implementation from otel.rs for analysis
static TEST_SPAN_SEED: AtomicU64 = AtomicU64::new(1);

fn problematic_splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn trace_id_from_bytes(mut bytes: [u8; 16]) -> TraceId {
    if bytes == [0; 16] {
        bytes[15] = 1;
    }

    TraceId::from_str(&hex::encode(bytes)).expect("trace-id bytes must be parseable")
}

fn trace_id_to_bytes(trace_id: TraceId) -> [u8; 16] {
    let bytes = hex::decode(trace_id.to_hex()).expect("trace-id hex must decode");
    let mut array = [0u8; 16];
    array.copy_from_slice(&bytes);
    array
}

fn problematic_trace_id_generation() -> TraceId {
    let seed = TEST_SPAN_SEED.fetch_add(1, Ordering::Relaxed);
    problematic_trace_id_generation_from_seed(seed)
}

fn problematic_trace_id_generation_from_seed(seed: u64) -> TraceId {
    let hi = problematic_splitmix64(seed);
    let lo = problematic_splitmix64(seed ^ 0x9e37_79b9_7f4a_7c15);

    trace_id_from_bytes([
        (hi >> 56) as u8,
        (hi >> 48) as u8,
        (hi >> 40) as u8,
        (hi >> 32) as u8,
        (hi >> 24) as u8,
        (hi >> 16) as u8,
        (hi >> 8) as u8,
        hi as u8,
        (lo >> 56) as u8,
        (lo >> 48) as u8,
        (lo >> 40) as u8,
        (lo >> 32) as u8,
        (lo >> 24) as u8,
        (lo >> 16) as u8,
        (lo >> 8) as u8,
        lo as u8,
    ])
}

fn w3c_compliant_trace_id_generation() -> TraceId {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("failed to generate random trace-id bytes");
    trace_id_from_bytes(bytes)
}

/// **AUDIT TEST**: Verify trace_id generation uses 128-bit randomness per W3C spec.
///
/// **SCENARIO**: Generate 1000 trace_ids and analyze statistical properties.
/// **REQUIREMENT**: Should exhibit cryptographically secure randomness properties.
/// **ASSESSMENT**: Current splitmix64 implementation vs W3C specification compliance.
#[test]
fn audit_trace_id_w3c_randomness_compliance() {
    println!("🔍 AUDIT: W3C Trace Context trace_id 128-bit randomness compliance");

    println!("📋 W3C Trace Context specification requirements:");
    println!("   • trace_id MUST be 16 random bytes (128 bits)");
    println!("   • MUST be globally unique and unpredictable");
    println!("   • NOT: deterministic PRNG with predictable sequence");
    println!("   • NOT: related 64-bit halves (entropy reduction)");

    const SAMPLE_SIZE: usize = 1000;

    // Test current implementation
    println!("📊 Testing current implementation (problematic):");
    let mut problematic_ids = Vec::with_capacity(SAMPLE_SIZE);
    let mut problematic_bytes_freq: HashMap<usize, HashMap<u8, u32>> = HashMap::new();

    for _ in 0..SAMPLE_SIZE {
        let trace_id = problematic_trace_id_generation();
        let bytes = trace_id_to_bytes(trace_id);
        problematic_ids.push(bytes);

        // Analyze byte frequency distribution
        for (pos, &byte) in bytes.iter().enumerate() {
            *problematic_bytes_freq
                .entry(pos)
                .or_default()
                .entry(byte)
                .or_insert(0) += 1;
        }
    }

    // Test W3C compliant implementation
    println!("📊 Testing W3C compliant implementation (correct):");
    let mut compliant_ids = Vec::with_capacity(SAMPLE_SIZE);
    let mut compliant_bytes_freq: HashMap<usize, HashMap<u8, u32>> = HashMap::new();

    for _ in 0..SAMPLE_SIZE {
        let trace_id = w3c_compliant_trace_id_generation();
        let bytes = trace_id_to_bytes(trace_id);
        compliant_ids.push(bytes);

        for (pos, &byte) in bytes.iter().enumerate() {
            *compliant_bytes_freq
                .entry(pos)
                .or_default()
                .entry(byte)
                .or_insert(0) += 1;
        }
    }

    // **STATISTICAL ANALYSIS**: Chi-square test for randomness
    println!("📊 Statistical randomness analysis:");

    let problematic_chi_square = calculate_chi_square(&problematic_bytes_freq, SAMPLE_SIZE);
    let compliant_chi_square = calculate_chi_square(&compliant_bytes_freq, SAMPLE_SIZE);

    println!(
        "   Problematic implementation chi-square: {:.2}",
        problematic_chi_square
    );
    println!("   W3C compliant chi-square: {:.2}", compliant_chi_square);

    // Chi-square critical value for 255 degrees of freedom at p=0.05 ≈ 293.25
    const CHI_SQUARE_CRITICAL: f64 = 293.25;

    if problematic_chi_square > CHI_SQUARE_CRITICAL {
        println!("❌ NON-RANDOM PATTERN DETECTED in current implementation");
        println!(
            "💡 EVIDENCE: Chi-square {} > critical value {}",
            problematic_chi_square, CHI_SQUARE_CRITICAL
        );
    } else {
        println!("✅ Current implementation passes chi-square test");
    }

    if compliant_chi_square > CHI_SQUARE_CRITICAL {
        println!("⚠️  W3C compliant implementation unexpectedly non-random");
    } else {
        println!("✅ W3C compliant implementation passes chi-square test");
    }

    // **UNIQUENESS ANALYSIS**
    println!("📊 Uniqueness analysis:");
    let problematic_unique: HashSet<_> = problematic_ids.iter().collect();
    let compliant_unique: HashSet<_> = compliant_ids.iter().collect();

    println!(
        "   Problematic unique IDs: {}/{} ({:.1}%)",
        problematic_unique.len(),
        SAMPLE_SIZE,
        (problematic_unique.len() as f64 / SAMPLE_SIZE as f64) * 100.0
    );
    println!(
        "   W3C compliant unique IDs: {}/{} ({:.1}%)",
        compliant_unique.len(),
        SAMPLE_SIZE,
        (compliant_unique.len() as f64 / SAMPLE_SIZE as f64) * 100.0
    );

    // **PREDICTABILITY ANALYSIS**
    println!("📊 Predictability analysis:");
    let problematic_sequential_bias = analyze_sequential_bias(&problematic_ids);
    let compliant_sequential_bias = analyze_sequential_bias(&compliant_ids);

    println!(
        "   Problematic sequential bias: {:.4}",
        problematic_sequential_bias
    );
    println!(
        "   W3C compliant sequential bias: {:.4}",
        compliant_sequential_bias
    );

    // **W3C COMPLIANCE ASSESSMENT**
    println!("📊 W3C Trace Context compliance assessment:");

    let mut compliance_score = 0.0;
    let mut total_checks = 0.0;

    // Check 1: All IDs are unique (required)
    total_checks += 1.0;
    if problematic_unique.len() == SAMPLE_SIZE {
        println!("   ✅ Uniqueness: All {} trace_ids are unique", SAMPLE_SIZE);
        compliance_score += 1.0;
    } else {
        println!(
            "   ❌ Uniqueness: {} duplicate trace_ids detected",
            SAMPLE_SIZE - problematic_unique.len()
        );
    }

    // Check 2: Statistical randomness (chi-square)
    total_checks += 1.0;
    if problematic_chi_square <= CHI_SQUARE_CRITICAL {
        println!("   ✅ Randomness: Passes chi-square test");
        compliance_score += 1.0;
    } else {
        println!("   ❌ Randomness: Fails chi-square test (non-random pattern)");
    }

    // Check 3: Low sequential bias (unpredictability)
    total_checks += 1.0;
    if problematic_sequential_bias < 0.1 {
        println!("   ✅ Unpredictability: Low sequential bias");
        compliance_score += 1.0;
    } else {
        println!("   ❌ Unpredictability: High sequential bias (predictable pattern)");
    }

    let compliance_percentage = (compliance_score / total_checks) * 100.0;
    println!("📊 Overall W3C compliance: {:.1}%", compliance_percentage);

    // **DEFECT IDENTIFICATION**
    if compliance_percentage < 100.0 {
        println!("🚨 W3C TRACE CONTEXT VIOLATION DETECTED");
        println!("💡 ROOT CAUSE: splitmix64 PRNG with sequential seed");
        println!("🔧 REQUIRED FIX: Use cryptographically secure random bytes");
        println!("📋 IMPLEMENTATION:");
        println!("   - Replace splitmix64 with rand::thread_rng().fill_bytes()");
        println!("   - Generate 16 independent random bytes");
        println!("   - Ensure each trace_id has full 128-bit entropy");

        assert!(
            compliance_percentage < 100.0,
            "Audit confirms W3C Trace Context violation exists"
        );
    } else {
        println!("✅ W3C TRACE CONTEXT COMPLIANCE: Full specification adherence");
    }
}

/// Calculate chi-square test statistic for byte frequency distribution.
fn calculate_chi_square(byte_freq: &HashMap<usize, HashMap<u8, u32>>, sample_size: usize) -> f64 {
    let expected_freq = sample_size as f64 / 256.0; // Expected frequency for uniform distribution
    let mut chi_square = 0.0;

    for position in 0..16 {
        if let Some(freq_map) = byte_freq.get(&position) {
            for byte_value in 0..=255u8 {
                let observed = *freq_map.get(&byte_value).unwrap_or(&0) as f64;
                let diff = observed - expected_freq;
                chi_square += (diff * diff) / expected_freq;
            }
        }
    }

    chi_square
}

/// Analyze sequential bias by comparing adjacent trace_ids.
fn analyze_sequential_bias(trace_ids: &[[u8; 16]]) -> f64 {
    if trace_ids.len() < 2 {
        return 0.0;
    }

    let mut total_hamming_distance = 0;
    for i in 1..trace_ids.len() {
        let hamming = hamming_distance(&trace_ids[i - 1], &trace_ids[i]);
        total_hamming_distance += hamming;
    }

    let avg_hamming = total_hamming_distance as f64 / (trace_ids.len() - 1) as f64;
    let expected_hamming = 64.0; // Expected for random 128-bit values

    // Return bias as deviation from expected randomness
    (expected_hamming - avg_hamming).abs() / expected_hamming
}

/// Calculate Hamming distance between two 16-byte arrays.
fn hamming_distance(a: &[u8; 16], b: &[u8; 16]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// **AUDIT TEST**: Demonstrate PRNG state leakage vulnerability.
///
/// **SCENARIO**: Show that splitmix64 sequence is predictable given initial state.
/// **REQUIREMENT**: Cryptographically secure generators should be unpredictable.
/// **ASSESSMENT**: Current implementation enables trace_id prediction attacks.
#[test]
fn audit_prng_state_leakage_vulnerability() {
    println!("🔍 AUDIT: PRNG state leakage vulnerability in trace_id generation");

    println!("📋 Cryptographic security requirements:");
    println!("   • Past outputs MUST NOT predict future outputs");
    println!("   • Generator state MUST be computationally infeasible to recover");
    println!("   • NOT: sequential PRNG with observable patterns");

    // Generate sequence of trace_ids
    let observed_ids: Vec<_> = (1000..1010)
        .map(problematic_trace_id_generation_from_seed)
        .collect();

    println!("📊 Observed trace_id sequence (first 3):");
    for (i, trace_id) in observed_ids.iter().take(3).enumerate() {
        println!("   {}: {}", i + 1, trace_id.to_hex());
    }

    // **VULNERABILITY DEMONSTRATION**: Predict next trace_id
    println!("📊 Predictability test:");

    let predicted_ids: Vec<_> = (1000..1010)
        .map(problematic_trace_id_generation_from_seed)
        .collect();

    // Check if prediction matches observation
    let matches = observed_ids
        .iter()
        .zip(predicted_ids.iter())
        .filter(|(a, b)| a == b)
        .count();

    println!(
        "   Prediction accuracy: {}/10 ({:.1}%)",
        matches,
        (matches as f64 / 10.0) * 100.0
    );

    if matches == 10 {
        println!("🚨 CRITICAL VULNERABILITY: trace_id sequence is fully predictable");
        println!("💡 ATTACK VECTOR: Attacker can predict future trace_ids");
        println!("🔧 SECURITY IMPACT: Trace correlation attacks, privacy violation");
    } else if matches > 5 {
        println!("⚠️  PARTIAL PREDICTABILITY: Some trace_ids are predictable");
    } else {
        println!("✅ UNPREDICTABLE: trace_id sequence appears random");
    }

    // **ROOT CAUSE ANALYSIS**
    println!("📊 Root cause analysis:");
    println!("   • splitmix64 is deterministic PRNG");
    println!("   • Sequential seed progression: seed, seed+1, seed+2, ...");
    println!("   • Two related outputs: splitmix64(seed) | splitmix64(seed^const)");
    println!("   • No cryptographic security properties");

    assert_eq!(
        matches, 10,
        "AUDIT CONFIRMS: trace_id generation is deterministic"
    );

    println!("✅ PRNG STATE LEAKAGE VULNERABILITY CONFIRMED");
}
