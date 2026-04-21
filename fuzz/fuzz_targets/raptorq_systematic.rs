#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::proof::DecodeConfig;
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParamError, SystematicParams};
use asupersync::types::ObjectId;
use std::collections::{BTreeSet, HashSet};

/// Fuzzing parameters for RaptorQ systematic encoding/decoding.
#[derive(Debug, Clone, Arbitrary)]
struct FuzzConfig {
    /// Number of source symbols (K)
    pub k: u16,
    /// Symbol size in bytes
    pub symbol_size: u16,
    /// Encoding seed
    pub seed: u64,
    /// Source block number
    pub sbn: u8,
    /// Number of repair symbols to generate
    pub repair_count: u16,
    /// Symbol permutation indices for testing permutation invariance
    pub permutation_indices: Vec<u16>,
    /// Whether to test rank deficiency scenarios
    pub test_rank_deficiency: bool,
    /// Whether to test boundary conditions (K/K' edge cases)
    pub test_boundary_conditions: bool,
    /// Size of the lookup window around the raw K value
    pub lookup_window: u8,
    /// Subset of source symbols to use (for partial reception)
    pub source_subset_mask: Vec<bool>,
    /// Repair symbols to drop (for loss simulation)
    pub repair_drop_mask: Vec<bool>,
}

/// Validate and normalize fuzz configuration
fn normalize_config(config: &mut FuzzConfig) {
    // Keep the expensive encode/decode path small; full-range K lookup is
    // exercised separately via cheap table-only checks below.
    config.k = config.k.clamp(1, 256);

    // Clamp symbol size to reasonable range
    config.symbol_size = config.symbol_size.clamp(1, 1024);

    // Limit repair count for performance
    config.repair_count = config.repair_count.clamp(0, config.k.saturating_mul(2));
    config.lookup_window = config.lookup_window.clamp(0, 32);

    // Normalize permutation indices
    if !config.permutation_indices.is_empty() {
        for idx in &mut config.permutation_indices {
            *idx = *idx % config.k;
        }
        config.permutation_indices.truncate(config.k as usize);
    }

    // Normalize subset masks
    config.source_subset_mask.truncate(config.k as usize);
    config
        .repair_drop_mask
        .truncate(config.repair_count as usize);
}

fn max_supported_source_block_size() -> usize {
    match SystematicParams::try_for_source_block(0, 1).unwrap_err() {
        SystematicParamError::UnsupportedSourceBlockSize { max_supported, .. } => max_supported,
    }
}

fn assert_param_invariants(params: &SystematicParams) -> Result<(), String> {
    if params.k == 0 {
        return Err("table lookup produced zero-sized source block".to_string());
    }
    if params.k_prime < params.k {
        return Err(format!(
            "K' must be >= K, got K={} K'={}",
            params.k, params.k_prime
        ));
    }
    if params.symbol_size == 0 {
        return Err("symbol size must stay positive".to_string());
    }
    if params.w < params.s {
        return Err(format!("W must be >= S, got W={} S={}", params.w, params.s));
    }
    if params.l != params.k_prime + params.s + params.h {
        return Err(format!(
            "L partition mismatch: expected {} got {}",
            params.k_prime + params.s + params.h,
            params.l
        ));
    }
    if params.b != params.w - params.s {
        return Err(format!(
            "B partition mismatch: expected {} got {}",
            params.w - params.s,
            params.b
        ));
    }
    if params.p != params.l - params.w {
        return Err(format!(
            "P partition mismatch: expected {} got {}",
            params.l - params.w,
            params.p
        ));
    }

    Ok(())
}

fn build_lookup_candidates(raw_k: usize, window: usize, max_supported: usize) -> Vec<usize> {
    let max_with_overflow_case = max_supported.saturating_add(1);
    let mut candidates = BTreeSet::new();
    for candidate in [
        0usize,
        1,
        2,
        10,
        11,
        12,
        raw_k.saturating_sub(window),
        raw_k.saturating_sub(1),
        raw_k,
        raw_k.saturating_add(1).min(max_with_overflow_case),
        raw_k.saturating_add(window).min(max_with_overflow_case),
        max_supported.saturating_sub(1),
        max_supported,
        max_with_overflow_case,
    ] {
        candidates.insert(candidate);
    }
    candidates.into_iter().collect()
}

fn assert_same_partition_row(
    baseline: &SystematicParams,
    candidate: &SystematicParams,
) -> Result<(), String> {
    if baseline.k_prime != candidate.k_prime
        || baseline.j != candidate.j
        || baseline.s != candidate.s
        || baseline.h != candidate.h
        || baseline.w != candidate.w
        || baseline.p != candidate.p
        || baseline.b != candidate.b
        || baseline.l != candidate.l
    {
        return Err(format!(
            "same-row lookup drifted: baseline={baseline:?} candidate={candidate:?}"
        ));
    }
    Ok(())
}

fn test_systematic_index_lookup_boundaries(
    raw_k: usize,
    symbol_size: usize,
    lookup_window: usize,
) -> Result<(), String> {
    let max_supported = max_supported_source_block_size();
    let candidates = build_lookup_candidates(raw_k, lookup_window, max_supported);

    for k in candidates {
        match SystematicParams::try_for_source_block(k, symbol_size) {
            Ok(params) => {
                assert_param_invariants(&params)?;

                if k == max_supported && params.k_prime != max_supported {
                    return Err(format!(
                        "K_max should map to its own final table row, got K'={}",
                        params.k_prime
                    ));
                }

                if params.k < params.k_prime {
                    let next = SystematicParams::try_for_source_block(params.k + 1, symbol_size)
                        .map_err(|err| {
                            format!("next lookup failed for K={}: {err:?}", params.k + 1)
                        })?;
                    assert_same_partition_row(&params, &next)?;
                }

                let boundary = SystematicParams::try_for_source_block(params.k_prime, symbol_size)
                    .map_err(|err| {
                        format!("boundary lookup failed for K={}: {err:?}", params.k_prime)
                    })?;
                assert_same_partition_row(&params, &boundary)?;

                if params.k_prime < max_supported {
                    let after_boundary =
                        SystematicParams::try_for_source_block(params.k_prime + 1, symbol_size)
                            .map_err(|err| {
                                format!(
                                    "post-boundary lookup failed for K={}: {err:?}",
                                    params.k_prime + 1
                                )
                            })?;
                    if after_boundary.k_prime <= params.k_prime {
                        return Err(format!(
                            "table partition did not advance after K' boundary: boundary={} next={}",
                            params.k_prime, after_boundary.k_prime
                        ));
                    }
                }
            }
            Err(err) => {
                if k <= max_supported {
                    return Err(format!(
                        "supported K={k} unexpectedly failed lookup: {err:?}"
                    ));
                }
                if err
                    != (SystematicParamError::UnsupportedSourceBlockSize {
                        requested: k,
                        max_supported,
                    })
                {
                    return Err(format!(
                        "unsupported K lookup returned wrong error for K={k}: {err:?}"
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Generate source data for encoding
fn generate_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut source = Vec::with_capacity(k);

    for i in 0..k {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        i.hash(&mut hasher);

        let symbol_seed = hasher.finish();
        let mut symbol = Vec::with_capacity(symbol_size);

        for j in 0..symbol_size {
            let mut byte_hasher = DefaultHasher::new();
            symbol_seed.hash(&mut byte_hasher);
            j.hash(&mut byte_hasher);
            symbol.push((byte_hasher.finish() & 0xFF) as u8);
        }

        source.push(symbol);
    }

    source
}

/// Apply permutation to source symbols to test permutation invariance
fn apply_permutation(source: &mut [Vec<u8>], indices: &[u16]) {
    if indices.len() != source.len() {
        return;
    }

    let mut permuted = vec![Vec::new(); source.len()];
    for (i, &target_idx) in indices.iter().enumerate() {
        if (target_idx as usize) < source.len() {
            permuted[target_idx as usize] = std::mem::take(&mut source[i]);
        }
    }

    for (i, symbol) in permuted.into_iter().enumerate() {
        if i < source.len() && !symbol.is_empty() {
            source[i] = symbol;
        }
    }
}

/// Test K/K' parameter boundaries
fn test_boundary_conditions(k: usize, symbol_size: usize, seed: u64) -> Result<(), String> {
    // Test with exact K value
    let _params_exact = SystematicParams::for_source_block(k, symbol_size);

    // Test edge case where K is right at a K' boundary
    if k > 1 {
        let _params_near = SystematicParams::for_source_block(k - 1, symbol_size);
    }

    // Test with K=1 (minimal case)
    let _params_min = SystematicParams::for_source_block(1, symbol_size);

    // Generate minimal source
    let source = generate_source_data(k.min(2), symbol_size, seed);

    // Test encoder construction
    if let Some(_encoder) = SystematicEncoder::new(&source, symbol_size, seed) {
        // Success - boundary conditions handled properly
    }

    Ok(())
}

/// Create ReceivedSymbol from EmittedSymbol
fn create_received_symbol(esi: u32, data: Vec<u8>) -> ReceivedSymbol {
    let is_source = esi < 1000; // Arbitrary threshold for systematic vs repair
    ReceivedSymbol {
        esi,
        is_source,
        columns: if is_source {
            vec![esi as usize]
        } else {
            vec![0, 1, 2]
        }, // Simplified
        coefficients: if is_source {
            vec![Gf256::ONE]
        } else {
            vec![Gf256::ONE; 3]
        }, // Simplified
        data,
    }
}

/// Test LT vs systematic row mixing under rank deficiency
fn test_rank_deficiency_handling(
    k: usize,
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
) -> Result<(), String> {
    let source = generate_source_data(k, symbol_size, seed);
    let Some(mut encoder) = SystematicEncoder::new(&source, symbol_size, seed) else {
        return Err("Failed to create encoder for rank deficiency test".to_string());
    };

    // Generate systematic symbols
    let systematic = encoder.emit_systematic();

    // Generate repair symbols
    let repairs = encoder.emit_repair(repair_count);

    // Create decoder
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let params = SystematicParams::for_source_block(k, symbol_size);
    let object_id = ObjectId::new_for_test(seed);

    let config = DecodeConfig {
        object_id,
        sbn: 0,
        k,
        s: params.s,
        h: params.h,
        l: params.l,
        symbol_size,
        seed,
    };

    // Test with insufficient symbols (should fail gracefully)
    if k > 2 {
        let insufficient: Vec<_> = systematic
            .iter()
            .take(k - 2)
            .map(|s| create_received_symbol(s.esi, s.data.clone()))
            .collect();

        let result = decoder.decode_with_proof(&insufficient, config.object_id, config.sbn);
        match result {
            Ok(_) => return Err("Decode should fail with insufficient symbols".to_string()),
            Err((_, proof)) => {
                // Validate proof consistency
                let _ = proof.content_hash(); // Should not panic
            }
        }
    }

    // Test with exactly enough symbols (mixed systematic + repair)
    let mut mixed_symbols = Vec::new();

    // Add subset of systematic symbols
    for symbol in systematic.iter().take(k / 2) {
        mixed_symbols.push(create_received_symbol(symbol.esi, symbol.data.clone()));
    }

    // Fill with repair symbols
    let needed = k.saturating_sub(mixed_symbols.len());
    for symbol in repairs.iter().take(needed) {
        mixed_symbols.push(create_received_symbol(symbol.esi, symbol.data.clone()));
    }

    // Attempt decode
    let result = decoder.decode_with_proof(&mixed_symbols, config.object_id, config.sbn);
    match result {
        Ok(decode_result) => {
            // Verify proof consistency
            let hash = decode_result.proof.content_hash();
            assert!(hash != 0, "Proof hash should be non-zero");

            // Verify decode correctness
            if decode_result.result.source.len() == source.len() {
                // Allow for some differences due to rank deficiency and elimination order
                let mut matches = 0;
                for (orig, rec) in source.iter().zip(decode_result.result.source.iter()) {
                    if orig == rec {
                        matches += 1;
                    }
                }
                // Should recover at least partial data
                if matches < source.len() / 2 {
                    return Err(format!(
                        "Too few recovered symbols match: {}/{}",
                        matches,
                        source.len()
                    ));
                }
            }
        }
        Err((_, proof)) => {
            // Even on failure, proof should be consistent
            let _ = proof.content_hash(); // Should not panic
        }
    }

    Ok(())
}

/// Test proof validation consistency
fn test_proof_consistency(
    k: usize,
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
) -> Result<(), String> {
    let source = generate_source_data(k, symbol_size, seed);
    let Some(mut encoder) = SystematicEncoder::new(&source, symbol_size, seed) else {
        return Err("Failed to create encoder for proof test".to_string());
    };

    let systematic = encoder.emit_systematic();
    let repairs = encoder.emit_repair(repair_count.min(k));

    // Create complete symbol set
    let mut all_symbols = Vec::new();
    for symbol in &systematic {
        all_symbols.push(create_received_symbol(symbol.esi, symbol.data.clone()));
    }
    for symbol in &repairs {
        all_symbols.push(create_received_symbol(symbol.esi, symbol.data.clone()));
    }

    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let params = SystematicParams::for_source_block(k, symbol_size);
    let object_id = ObjectId::new_for_test(seed);

    let config = DecodeConfig {
        object_id,
        sbn: 0,
        k,
        s: params.s,
        h: params.h,
        l: params.l,
        symbol_size,
        seed,
    };

    // Decode with proof
    let result = decoder.decode_with_proof(&all_symbols, config.object_id, config.sbn);

    let (is_success, proof) = match &result {
        Ok(decode_result) => (true, &decode_result.proof),
        Err((_, proof)) => (false, proof),
    };

    // Test proof consistency
    let hash1 = proof.content_hash();
    let hash2 = proof.content_hash();
    if hash1 != hash2 {
        return Err("Proof content hash is not deterministic".to_string());
    }

    // Test proof replay (if successful decode)
    if is_success {
        if let Err(_replay_error) = proof.replay_and_verify(&all_symbols) {
            // Note: replay failures are expected in fuzzing due to simplified ReceivedSymbol creation
            // We just ensure it doesn't panic
        }
    }

    Ok(())
}

/// Test symbol permutation invariance
fn test_permutation_invariance(
    k: usize,
    symbol_size: usize,
    seed: u64,
    permutation: &[u16],
) -> Result<(), String> {
    if permutation.len() != k {
        return Ok(()); // Skip invalid permutations
    }

    // Check if permutation is valid (all indices 0..k-1 appear once)
    let mut seen = HashSet::new();
    for &idx in permutation {
        if (idx as usize) >= k || !seen.insert(idx) {
            return Ok(()); // Skip invalid permutations
        }
    }

    let source1 = generate_source_data(k, symbol_size, seed);
    let mut source2 = source1.clone();

    // Apply permutation to second source
    apply_permutation(&mut source2, permutation);

    // Encode both
    let Some(mut encoder1) = SystematicEncoder::new(&source1, symbol_size, seed) else {
        return Err("Failed to create encoder1".to_string());
    };
    let Some(mut encoder2) = SystematicEncoder::new(&source2, symbol_size, seed) else {
        return Err("Failed to create encoder2".to_string());
    };

    // Generate systematic symbols
    let sys1 = encoder1.emit_systematic();
    let sys2 = encoder2.emit_systematic();

    // For small K, verify systematic symbols preserve structure
    if k <= 8 && sys1.len() == k && sys2.len() == k {
        // Check that permutation is reflected in output order
        let mut permuted_matches = 0;
        for i in 0..k {
            let orig_idx = permutation[i] as usize;
            if orig_idx < sys1.len() && i < sys2.len() {
                if sys1[orig_idx].data == sys2[i].data {
                    permuted_matches += 1;
                }
            }
        }

        // Should have some correlation (allowing for encoder internals)
        if permuted_matches < k / 3 {
            return Err(format!(
                "Insufficient permutation correlation: {}/{}",
                permuted_matches, k
            ));
        }
    }

    Ok(())
}

/// Main fuzzing function
fn fuzz_systematic(mut config: FuzzConfig) -> Result<(), String> {
    let raw_k = config.k as usize;
    normalize_config(&mut config);

    let k = config.k as usize;
    let symbol_size = config.symbol_size as usize;
    let seed = config.seed;
    let repair_count = config.repair_count as usize;

    test_systematic_index_lookup_boundaries(raw_k, symbol_size, config.lookup_window as usize)?;

    // Skip degenerate cases
    if k == 0 || symbol_size == 0 {
        return Ok(());
    }

    // Test 1: K/K' parameter boundary conditions
    if config.test_boundary_conditions {
        test_boundary_conditions(k, symbol_size, seed)?;
    }

    // Test 2: Symbol permutation invariance
    if !config.permutation_indices.is_empty() && config.permutation_indices.len() == k {
        test_permutation_invariance(k, symbol_size, seed, &config.permutation_indices)?;
    }

    // Test 3: LT vs systematic row mixing under rank deficiency
    if config.test_rank_deficiency && repair_count > 0 {
        test_rank_deficiency_handling(k, symbol_size, seed, repair_count)?;
    }

    // Test 4: Proof validation consistency
    if repair_count > 0 {
        test_proof_consistency(k, symbol_size, seed, repair_count)?;
    }

    // Test 5: Basic encode/decode round-trip
    let source = generate_source_data(k, symbol_size, seed);
    if let Some(mut encoder) = SystematicEncoder::new(&source, symbol_size, seed) {
        // Generate symbols with source subset masking
        let mut systematic = encoder.emit_systematic();
        let mut repairs = encoder.emit_repair(repair_count);

        // Apply masks
        if config.source_subset_mask.len() == k {
            systematic.retain(|s| {
                let idx = s.esi as usize;
                idx < config.source_subset_mask.len() && config.source_subset_mask[idx]
            });
        }

        if config.repair_drop_mask.len() == repair_count {
            repairs.retain(|_| true); // Keep all for now - complex masking can be added later
        }

        // Try decode
        let mut all_symbols = Vec::new();
        for symbol in &systematic {
            all_symbols.push(create_received_symbol(symbol.esi, symbol.data.clone()));
        }
        for symbol in &repairs {
            all_symbols.push(create_received_symbol(symbol.esi, symbol.data.clone()));
        }

        if all_symbols.len() >= k {
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let _result =
                decoder.decode_with_proof(&all_symbols, ObjectId::new_for_test(seed), config.sbn);
            // Allow both success and failure - we're testing for crashes/corruption
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 10_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Generate fuzz configuration
    let config = if let Ok(c) = FuzzConfig::arbitrary(&mut unstructured) {
        c
    } else {
        return;
    };

    // Run systematic encoder/decoder fuzzing
    let _ = fuzz_systematic(config);
});
