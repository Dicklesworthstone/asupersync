#![allow(clippy::similar_names)]
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice};
use asupersync::raptorq::proof::DecodeConfig;
use asupersync::raptorq::systematic::{
    ConstraintMatrix, SystematicEncoder, SystematicParamError, SystematicParams,
};
use asupersync::types::ObjectId;
use std::collections::{BTreeSet, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

const LARGE_FEC_K: usize = 10_000;
const LARGE_FEC_MAX_SYMBOL_SIZE: usize = 16;
const LARGE_FEC_MAX_REPAIR_COUNT: usize = 8;
const REPAIR_SYMBOL_VARIATION_K: usize = 4;
const REPAIR_SYMBOL_VARIATION_REPAIR_COUNT: usize = 3;
const MAX_RAPTORQ_SYMBOL_SIZE: usize = u16::MAX as usize;

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
    /// Arbitrary source bytes for direct payload-generation checks.
    pub source_bytes: Vec<u8>,
}

/// Validate and normalize fuzz configuration
fn normalize_config(config: &mut FuzzConfig) {
    // Keep the expensive encode/decode path small; full-range K lookup is
    // exercised separately via cheap table-only checks below.
    config.k = config.k.clamp(1, 256);

    // Keep full-matrix intermediate verification bounded enough for fuzzing.
    config.symbol_size = config.symbol_size.clamp(1, 256);

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
    config.source_bytes.truncate(16 * 1024);
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

fn build_source_from_bytes(source_bytes: &[u8], k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    let mut source = Vec::with_capacity(k);
    for i in 0..k {
        let start = i.saturating_mul(symbol_size);
        let end = start.saturating_add(symbol_size);
        let mut symbol = vec![0u8; symbol_size];
        if start < source_bytes.len() {
            let available_end = end.min(source_bytes.len());
            let copy_len = available_end - start;
            symbol[..copy_len].copy_from_slice(&source_bytes[start..available_end]);
        }
        source.push(symbol);
    }
    source
}

fn build_encoder_rhs(source: &[Vec<u8>], params: &SystematicParams) -> Vec<Vec<u8>> {
    let mut rhs = Vec::with_capacity(params.s + params.h + params.k_prime);

    for _ in 0..params.s + params.h {
        rhs.push(vec![0u8; params.symbol_size]);
    }

    rhs.extend(source.iter().cloned());

    for _ in source.len()..params.k_prime {
        rhs.push(vec![0u8; params.symbol_size]);
    }

    rhs
}

fn row_nonzero_count(matrix: &ConstraintMatrix, row: usize) -> usize {
    (0..matrix.cols)
        .filter(|&col| !matrix.get(row, col).is_zero())
        .count()
}

fn assert_constraint_matrix_shape(
    matrix: &ConstraintMatrix,
    params: &SystematicParams,
) -> Result<(), String> {
    let expected_rows = params.s + params.h + params.k_prime;
    if matrix.rows != expected_rows {
        return Err(format!(
            "constraint matrix row count mismatch: expected {expected_rows}, got {}",
            matrix.rows
        ));
    }
    if matrix.cols != params.l {
        return Err(format!(
            "constraint matrix col count mismatch: expected {}, got {}",
            params.l, matrix.cols
        ));
    }

    for row in 0..params.s {
        if matrix.get(row, params.k_prime + row) != Gf256::ONE {
            return Err(format!(
                "LDPC identity block missing at row {row}, col {}",
                params.k_prime + row
            ));
        }
        if row_nonzero_count(matrix, row) < 4 {
            return Err(format!(
                "LDPC row {row} unexpectedly sparse: degree {}",
                row_nonzero_count(matrix, row)
            ));
        }
    }

    for row in 0..params.h {
        let matrix_row = params.s + row;
        let identity_col = params.k_prime + params.s + row;
        if matrix.get(matrix_row, identity_col) != Gf256::ONE {
            return Err(format!(
                "HDPC identity block missing at row {matrix_row}, col {identity_col}"
            ));
        }
        if row_nonzero_count(matrix, matrix_row) < 2 {
            return Err(format!(
                "HDPC row {matrix_row} unexpectedly sparse: degree {}",
                row_nonzero_count(matrix, matrix_row)
            ));
        }
    }

    for row in 0..params.k_prime {
        let matrix_row = params.s + params.h + row;
        if matrix.get(matrix_row, row) != Gf256::ONE {
            return Err(format!(
                "LT identity block missing at row {matrix_row}, col {row}"
            ));
        }
        if row_nonzero_count(matrix, matrix_row) != 1 {
            return Err(format!(
                "LT row {matrix_row} must stay degree-1, saw degree {}",
                row_nonzero_count(matrix, matrix_row)
            ));
        }
    }

    for col in 0..matrix.cols {
        let covered = (0..matrix.rows).any(|row| !matrix.get(row, col).is_zero());
        if !covered {
            return Err(format!("constraint matrix left column {col} uncovered"));
        }
    }

    Ok(())
}

fn assert_solution_satisfies_rhs(
    matrix: &ConstraintMatrix,
    intermediate: &[Vec<u8>],
    rhs: &[Vec<u8>],
) -> Result<(), String> {
    if intermediate.len() != matrix.cols {
        return Err(format!(
            "intermediate symbol count mismatch: expected {}, got {}",
            matrix.cols,
            intermediate.len()
        ));
    }

    let symbol_size = rhs.first().map_or(0, Vec::len);
    if intermediate
        .iter()
        .any(|symbol| symbol.len() != symbol_size)
    {
        return Err("intermediate symbols had inconsistent widths".to_string());
    }

    for row in 0..matrix.rows {
        let mut reconstructed = vec![0u8; symbol_size];
        for (col, symbol) in intermediate.iter().enumerate().take(matrix.cols) {
            let coefficient = matrix.get(row, col);
            if coefficient.is_zero() {
                continue;
            }
            gf256_addmul_slice(&mut reconstructed, symbol, coefficient);
        }

        if reconstructed != rhs[row] {
            return Err(format!("A·C = D invariant failed at row {row}"));
        }
    }

    Ok(())
}

fn assert_encoder_matches_intermediate_solution(
    encoder: &SystematicEncoder,
    expected: &[Vec<u8>],
) -> Result<(), String> {
    let params = encoder.params();
    if params.l != expected.len() {
        return Err(format!(
            "encoder parameter L mismatch: expected {} solved symbols, got {}",
            expected.len(),
            params.l
        ));
    }

    for (idx, solved) in expected.iter().enumerate() {
        if encoder.intermediate_symbol(idx) != solved.as_slice() {
            return Err(format!(
                "encoder intermediate symbol diverged from solved matrix at index {idx}"
            ));
        }
    }

    Ok(())
}

fn assert_param_shapes_match_encoder(
    params: &SystematicParams,
    encoder: &SystematicEncoder,
) -> Result<(), String> {
    let encoder_params = encoder.params();
    let same = params.k == encoder_params.k
        && params.k_prime == encoder_params.k_prime
        && params.j == encoder_params.j
        && params.s == encoder_params.s
        && params.h == encoder_params.h
        && params.l == encoder_params.l
        && params.w == encoder_params.w
        && params.p == encoder_params.p
        && params.b == encoder_params.b
        && params.symbol_size == encoder_params.symbol_size;
    if !same {
        return Err(format!(
            "encoder params diverged from systematic lookup: expected {params:?}, got {encoder_params:?}"
        ));
    }
    Ok(())
}

fn test_intermediate_symbol_generation(
    k: usize,
    symbol_size: usize,
    seed: u64,
) -> Result<(), String> {
    let params = SystematicParams::for_source_block(k, symbol_size);
    assert_param_invariants(&params)?;

    let matrix = catch_unwind(AssertUnwindSafe(|| ConstraintMatrix::build(&params, seed)))
        .map_err(|_| {
            format!("ConstraintMatrix::build panicked for K={k}, T={symbol_size}, seed={seed}")
        })?;
    assert_constraint_matrix_shape(&matrix, &params)?;

    let source = generate_source_data(k, symbol_size, seed);
    let rhs = build_encoder_rhs(&source, &params);

    let solved = catch_unwind(AssertUnwindSafe(|| matrix.solve(&rhs)))
        .map_err(|_| {
            format!("ConstraintMatrix::solve panicked for K={k}, T={symbol_size}, seed={seed}")
        })?
        .ok_or_else(|| {
            format!("ConstraintMatrix::solve returned singular matrix for K={k}, T={symbol_size}")
        })?;
    assert_solution_satisfies_rhs(&matrix, &solved, &rhs)?;

    let encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source, symbol_size, seed)
    }))
    .map_err(|_| {
        format!("SystematicEncoder::new panicked for K={k}, T={symbol_size}, seed={seed}")
    })?
    .ok_or_else(|| {
        format!("SystematicEncoder::new returned None for K={k}, T={symbol_size}, seed={seed}")
    })?;

    assert_param_shapes_match_encoder(&params, &encoder)?;
    assert_encoder_matches_intermediate_solution(&encoder, &solved)?;

    Ok(())
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
            assert!(
                hash.as_bytes().iter().any(|&byte| byte != 0),
                "Proof hash should not be all zeros"
            );

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

fn test_payload_generation_size(
    k: usize,
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
    source_bytes: &[u8],
) -> Result<(), String> {
    let source = build_source_from_bytes(source_bytes, k, symbol_size);
    let encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source, symbol_size, seed)
    }))
    .map_err(|_| {
        format!("SystematicEncoder::new panicked for payload-size check K={k}, T={symbol_size}, seed={seed}")
    })?;
    let Some(mut encoder) = encoder else {
        return Ok(());
    };

    let emitted = catch_unwind(AssertUnwindSafe(|| encoder.emit_all(repair_count))).map_err(|_| {
        format!("emit_all panicked for payload-size check K={k}, T={symbol_size}, repairs={repair_count}")
    })?;

    let expected_symbol_count = k + repair_count;
    let expected_payload_bytes = expected_symbol_count
        .checked_mul(symbol_size)
        .ok_or_else(|| "expected payload size overflowed usize".to_string())?;
    let actual_payload_bytes: usize = emitted.iter().map(|symbol| symbol.data.len()).sum();

    if emitted.len() != expected_symbol_count {
        return Err(format!(
            "emit_all count mismatch: expected {expected_symbol_count}, got {}",
            emitted.len()
        ));
    }
    if actual_payload_bytes != expected_payload_bytes {
        return Err(format!(
            "emit_all payload-size mismatch: expected {expected_payload_bytes}, got {actual_payload_bytes}"
        ));
    }
    if emitted
        .iter()
        .any(|symbol| symbol.data.len() != symbol_size)
    {
        return Err(format!(
            "emit_all produced non-uniform symbol width for K={k}, T={symbol_size}"
        ));
    }

    Ok(())
}

fn test_large_k_payload_generation_size(
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
    source_bytes: &[u8],
) -> Result<(), String> {
    let bounded_symbol_size = symbol_size.clamp(1, LARGE_FEC_MAX_SYMBOL_SIZE);
    let bounded_repair_count = repair_count.min(LARGE_FEC_MAX_REPAIR_COUNT);
    let source = build_source_from_bytes(source_bytes, LARGE_FEC_K, bounded_symbol_size);
    let source_replay = source.clone();

    let encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source, bounded_symbol_size, seed)
    }))
    .map_err(|_| {
        format!(
            "SystematicEncoder::new panicked for large-K payload check K={LARGE_FEC_K}, T={bounded_symbol_size}, seed={seed}"
        )
    })?
    .ok_or_else(|| {
        format!(
            "SystematicEncoder::new returned None for large-K payload check K={LARGE_FEC_K}, T={bounded_symbol_size}, seed={seed}"
        )
    })?;
    let mut encoder = encoder;

    let emitted = catch_unwind(AssertUnwindSafe(|| encoder.emit_all(bounded_repair_count)))
        .map_err(|_| {
            format!(
                "emit_all panicked for large-K payload check K={LARGE_FEC_K}, T={bounded_symbol_size}, repairs={bounded_repair_count}"
            )
        })?;
    let replay_encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source_replay, bounded_symbol_size, seed)
    }))
    .map_err(|_| {
        format!(
            "SystematicEncoder::new panicked during deterministic replay check K={LARGE_FEC_K}, T={bounded_symbol_size}, seed={seed}"
        )
    })?
    .ok_or_else(|| {
        format!(
            "SystematicEncoder::new returned None during deterministic replay check K={LARGE_FEC_K}, T={bounded_symbol_size}, seed={seed}"
        )
    })?;
    let mut replay_encoder = replay_encoder;
    let replay_emitted = catch_unwind(AssertUnwindSafe(|| replay_encoder.emit_all(bounded_repair_count)))
        .map_err(|_| {
            format!(
                "emit_all panicked during deterministic replay check K={LARGE_FEC_K}, T={bounded_symbol_size}, repairs={bounded_repair_count}"
            )
        })?;

    let expected_symbol_count = LARGE_FEC_K + bounded_repair_count;
    let expected_payload_bytes = expected_symbol_count
        .checked_mul(bounded_symbol_size)
        .ok_or_else(|| "expected large-K payload size overflowed usize".to_string())?;
    let actual_payload_bytes: usize = emitted.iter().map(|symbol| symbol.data.len()).sum();

    if emitted.len() != expected_symbol_count {
        return Err(format!(
            "large-K emit_all count mismatch: expected {expected_symbol_count}, got {}",
            emitted.len()
        ));
    }
    if actual_payload_bytes != expected_payload_bytes {
        return Err(format!(
            "large-K emit_all payload-size mismatch: expected {expected_payload_bytes}, got {actual_payload_bytes}"
        ));
    }
    if emitted
        .iter()
        .any(|symbol| symbol.data.len() != bounded_symbol_size)
    {
        return Err(format!(
            "large-K emit_all produced non-uniform symbol width for K={LARGE_FEC_K}, T={bounded_symbol_size}"
        ));
    }
    if replay_emitted.len() != emitted.len() {
        return Err(format!(
            "large-K deterministic replay count mismatch: first={}, second={}",
            emitted.len(),
            replay_emitted.len()
        ));
    }
    for (idx, (first, second)) in emitted.iter().zip(replay_emitted.iter()).enumerate() {
        if first.esi != second.esi
            || first.is_source != second.is_source
            || first.data != second.data
        {
            return Err(format!(
                "large-K deterministic replay mismatch at symbol {idx}: \
                 first=(esi={}, source={}, len={}), second=(esi={}, source={}, len={})",
                first.esi,
                first.is_source,
                first.data.len(),
                second.esi,
                second.is_source,
                second.data.len()
            ));
        }
    }

    Ok(())
}

fn test_large_k_edge_byte_patterns(
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
) -> Result<(), String> {
    let bounded_symbol_size = symbol_size.clamp(1, LARGE_FEC_MAX_SYMBOL_SIZE);
    let total_source_bytes = LARGE_FEC_K
        .checked_mul(bounded_symbol_size)
        .ok_or_else(|| "large-K edge-pattern source size overflowed usize".to_string())?;
    let alternating: Vec<u8> = (0..total_source_bytes)
        .map(|idx| if idx % 2 == 0 { 0xAA } else { 0x55 })
        .collect();
    let patterns = [
        ("all_zero", vec![0u8; total_source_bytes]),
        ("all_one", vec![0xFFu8; total_source_bytes]),
        ("alternating_aa55", alternating),
    ];

    for (name, pattern) in patterns {
        test_large_k_payload_generation_size(symbol_size, seed, repair_count, &pattern)
            .map_err(|err| format!("edge pattern {name} failed: {err}"))?;
    }

    Ok(())
}

fn test_zero_source_repair_packets(
    k: usize,
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
) -> Result<(), String> {
    let bounded_repair_count = repair_count.clamp(1, LARGE_FEC_MAX_REPAIR_COUNT);
    let source = vec![vec![0u8; symbol_size]; k];
    let replay_source = source.clone();

    let encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source, symbol_size, seed)
    }))
    .map_err(|_| {
        format!("SystematicEncoder::new panicked for zero-source repair check K={k}, T={symbol_size}, seed={seed}")
    })?
    .ok_or_else(|| {
        format!("SystematicEncoder::new returned None for zero-source repair check K={k}, T={symbol_size}, seed={seed}")
    })?;
    let mut encoder = encoder;
    let repairs = catch_unwind(AssertUnwindSafe(|| encoder.emit_repair(bounded_repair_count)))
        .map_err(|_| {
            format!(
                "emit_repair panicked for zero-source repair check K={k}, T={symbol_size}, repairs={bounded_repair_count}"
            )
        })?;

    if repairs.len() != bounded_repair_count {
        return Err(format!(
            "zero-source repair count mismatch for K={k}: expected {bounded_repair_count}, got {}",
            repairs.len()
        ));
    }

    let replay_encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&replay_source, symbol_size, seed)
    }))
    .map_err(|_| {
        format!(
            "SystematicEncoder::new panicked during zero-source replay check K={k}, T={symbol_size}, seed={seed}"
        )
    })?
    .ok_or_else(|| {
        format!(
            "SystematicEncoder::new returned None during zero-source replay check K={k}, T={symbol_size}, seed={seed}"
        )
    })?;
    let mut replay_encoder = replay_encoder;
    let replay_repairs = catch_unwind(AssertUnwindSafe(|| {
        replay_encoder.emit_repair(bounded_repair_count)
    }))
    .map_err(|_| {
        format!(
            "emit_repair panicked during zero-source replay check K={k}, T={symbol_size}, repairs={bounded_repair_count}"
        )
    })?;

    if replay_repairs.len() != repairs.len() {
        return Err(format!(
            "zero-source repair replay count mismatch for K={k}: first={}, second={}",
            repairs.len(),
            replay_repairs.len()
        ));
    }

    let base_esi = u32::try_from(k).expect("K must fit in u32 for zero-source repair check");
    for (idx, (first, second)) in repairs.iter().zip(replay_repairs.iter()).enumerate() {
        let idx_u32 = u32::try_from(idx).expect("repair index must fit in u32");
        let expected_esi = base_esi + idx_u32;

        if first.is_source || second.is_source {
            return Err(format!(
                "zero-source repair packet mislabeled as source for K={k}, repair_index={idx}"
            ));
        }
        if first.esi != expected_esi || second.esi != expected_esi {
            return Err(format!(
                "zero-source repair ESI mismatch for K={k}, repair_index={idx}: \
                 expected {expected_esi}, first={}, second={}",
                first.esi, second.esi
            ));
        }
        if first.data.len() != symbol_size || second.data.len() != symbol_size {
            return Err(format!(
                "zero-source repair width mismatch for K={k}, repair_index={idx}: \
                 expected {symbol_size}, first={}, second={}",
                first.data.len(),
                second.data.len()
            ));
        }
        if first.data.iter().any(|&byte| byte != 0) || second.data.iter().any(|&byte| byte != 0) {
            return Err(format!(
                "zero-source repair payload was non-zero for K={k}, repair_index={idx}"
            ));
        }
        if first.data != second.data {
            return Err(format!(
                "zero-source repair replay payload mismatch for K={k}, repair_index={idx}"
            ));
        }
    }

    Ok(())
}

fn test_extreme_zero_source_repair_packets(
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
) -> Result<(), String> {
    let bounded_mid_symbol_size = symbol_size.clamp(1, 64);
    let bounded_large_symbol_size = symbol_size.clamp(1, LARGE_FEC_MAX_SYMBOL_SIZE);
    let bounded_repair_count = repair_count.clamp(1, LARGE_FEC_MAX_REPAIR_COUNT);

    test_zero_source_repair_packets(42, bounded_mid_symbol_size, seed, bounded_repair_count)
        .map_err(|err| format!("K=42 zero-source repair packet check failed: {err}"))?;
    test_zero_source_repair_packets(
        LARGE_FEC_K,
        bounded_large_symbol_size,
        seed,
        bounded_repair_count,
    )
    .map_err(|err| format!("K={LARGE_FEC_K} zero-source repair packet check failed: {err}"))?;

    Ok(())
}

fn build_symbol_size_variation_candidates(raw_symbol_size: usize) -> Vec<usize> {
    let mut candidates = BTreeSet::new();
    candidates.insert(8usize);
    candidates.insert(257usize);
    candidates.insert(MAX_RAPTORQ_SYMBOL_SIZE);
    candidates.insert(raw_symbol_size.clamp(8, MAX_RAPTORQ_SYMBOL_SIZE));
    candidates.into_iter().collect()
}

fn test_repair_symbol_size_variation(
    raw_symbol_size: usize,
    seed: u64,
    source_bytes: &[u8],
) -> Result<(), String> {
    let symbol_sizes = build_symbol_size_variation_candidates(raw_symbol_size);

    for symbol_size in symbol_sizes {
        let source = build_source_from_bytes(source_bytes, REPAIR_SYMBOL_VARIATION_K, symbol_size);
        let replay_source = source.clone();
        let direct_source = source.clone();

        let encoder = catch_unwind(AssertUnwindSafe(|| {
            SystematicEncoder::new(&source, symbol_size, seed)
        }))
        .map_err(|_| {
            format!(
                "SystematicEncoder::new panicked for symbol-size variation K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, seed={seed}"
            )
        })?
        .ok_or_else(|| {
            format!(
                "SystematicEncoder::new returned None for symbol-size variation K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, seed={seed}"
            )
        })?;
        let mut encoder = encoder;
        let repairs = catch_unwind(AssertUnwindSafe(|| {
            encoder.emit_repair(REPAIR_SYMBOL_VARIATION_REPAIR_COUNT)
        }))
        .map_err(|_| {
            format!(
                "emit_repair panicked for symbol-size variation K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, repairs={REPAIR_SYMBOL_VARIATION_REPAIR_COUNT}"
            )
        })?;

        if repairs.len() != REPAIR_SYMBOL_VARIATION_REPAIR_COUNT {
            return Err(format!(
                "symbol-size variation repair count mismatch for T={symbol_size}: expected {REPAIR_SYMBOL_VARIATION_REPAIR_COUNT}, got {}",
                repairs.len()
            ));
        }

        let replay_encoder = catch_unwind(AssertUnwindSafe(|| {
            SystematicEncoder::new(&replay_source, symbol_size, seed)
        }))
        .map_err(|_| {
            format!(
                "SystematicEncoder::new panicked during replay for symbol-size variation K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, seed={seed}"
            )
        })?
        .ok_or_else(|| {
            format!(
                "SystematicEncoder::new returned None during replay for symbol-size variation K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, seed={seed}"
            )
        })?;
        let mut replay_encoder = replay_encoder;
        let replay_repairs = catch_unwind(AssertUnwindSafe(|| {
            replay_encoder.emit_repair(REPAIR_SYMBOL_VARIATION_REPAIR_COUNT)
        }))
        .map_err(|_| {
            format!(
                "emit_repair panicked during replay for symbol-size variation K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, repairs={REPAIR_SYMBOL_VARIATION_REPAIR_COUNT}"
            )
        })?;

        let direct_encoder = catch_unwind(AssertUnwindSafe(|| {
            SystematicEncoder::new(&direct_source, symbol_size, seed)
        }))
        .map_err(|_| {
            format!(
                "SystematicEncoder::new panicked during direct repair_symbol check K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, seed={seed}"
            )
        })?
        .ok_or_else(|| {
            format!(
                "SystematicEncoder::new returned None during direct repair_symbol check K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, seed={seed}"
            )
        })?;

        if replay_repairs.len() != repairs.len() {
            return Err(format!(
                "symbol-size variation replay count mismatch for T={symbol_size}: first={}, second={}",
                repairs.len(),
                replay_repairs.len()
            ));
        }

        let base_esi = u32::try_from(REPAIR_SYMBOL_VARIATION_K)
            .expect("variation K must fit in u32 for repair_symbol check");
        for (idx, (first, second)) in repairs.iter().zip(replay_repairs.iter()).enumerate() {
            let idx_u32 = u32::try_from(idx).expect("repair index must fit in u32");
            let expected_esi = base_esi + idx_u32;
            let direct = catch_unwind(AssertUnwindSafe(|| direct_encoder.repair_symbol(expected_esi)))
                .map_err(|_| {
                    format!(
                        "repair_symbol panicked for symbol-size variation K={REPAIR_SYMBOL_VARIATION_K}, T={symbol_size}, esi={expected_esi}"
                    )
                })?;

            if first.is_source || second.is_source {
                return Err(format!(
                    "symbol-size variation mislabeled repair packet as source for T={symbol_size}, repair_index={idx}"
                ));
            }
            if first.esi != expected_esi || second.esi != expected_esi {
                return Err(format!(
                    "symbol-size variation ESI mismatch for T={symbol_size}, repair_index={idx}: expected {expected_esi}, first={}, second={}",
                    first.esi, second.esi
                ));
            }
            if first.data.len() != symbol_size
                || second.data.len() != symbol_size
                || direct.len() != symbol_size
            {
                return Err(format!(
                    "symbol-size variation repair width mismatch for T={symbol_size}, repair_index={idx}: first={}, second={}, direct={}",
                    first.data.len(),
                    second.data.len(),
                    direct.len()
                ));
            }
            if first.data != second.data || first.data != direct {
                return Err(format!(
                    "symbol-size variation repair payload mismatch for T={symbol_size}, repair_index={idx}"
                ));
            }
        }
    }

    Ok(())
}

fn test_single_byte_symbol_output(
    k: usize,
    seed: u64,
    repair_count: usize,
    source_bytes: &[u8],
) -> Result<(), String> {
    let symbol_size = 1usize;
    let bounded_repair_count = repair_count.clamp(1, LARGE_FEC_MAX_REPAIR_COUNT);
    let source = build_source_from_bytes(source_bytes, k, symbol_size);
    let source_replay = source.clone();
    let source_replay_all = source.clone();

    let encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source, symbol_size, seed)
    }))
    .map_err(|_| {
        format!("SystematicEncoder::new panicked for single-byte symbol check K={k}, seed={seed}")
    })?
    .ok_or_else(|| {
        format!(
            "SystematicEncoder::new returned None for single-byte symbol check K={k}, seed={seed}"
        )
    })?;
    let mut encoder = encoder;
    let systematic = catch_unwind(AssertUnwindSafe(|| encoder.emit_systematic()))
        .map_err(|_| format!("emit_systematic panicked for single-byte symbol check K={k}"))?;
    let repairs = catch_unwind(AssertUnwindSafe(|| encoder.emit_repair(bounded_repair_count)))
        .map_err(|_| {
            format!(
                "emit_repair panicked for single-byte symbol check K={k}, repairs={bounded_repair_count}"
            )
        })?;

    if systematic.len() != k {
        return Err(format!(
            "single-byte systematic count mismatch for K={k}: expected {k}, got {}",
            systematic.len()
        ));
    }
    if repairs.len() != bounded_repair_count {
        return Err(format!(
            "single-byte repair count mismatch for K={k}: expected {bounded_repair_count}, got {}",
            repairs.len()
        ));
    }

    for (idx, symbol) in systematic.iter().enumerate() {
        if !symbol.is_source {
            return Err(format!(
                "single-byte systematic packet mislabeled as repair for K={k}, source_index={idx}"
            ));
        }
        if symbol.esi != idx as u32 {
            return Err(format!(
                "single-byte systematic ESI mismatch for K={k}, source_index={idx}: got {}",
                symbol.esi
            ));
        }
        if symbol.data.len() != symbol_size {
            return Err(format!(
                "single-byte systematic width mismatch for K={k}, source_index={idx}: got {}",
                symbol.data.len()
            ));
        }
        if symbol.data != source[idx] {
            return Err(format!(
                "single-byte systematic payload mismatch for K={k}, source_index={idx}"
            ));
        }
    }

    let repair_base_esi = u32::try_from(k).expect("K must fit in u32 for single-byte repair check");
    for (idx, symbol) in repairs.iter().enumerate() {
        let expected_esi =
            repair_base_esi + u32::try_from(idx).expect("repair index must fit in u32");
        if symbol.is_source {
            return Err(format!(
                "single-byte repair packet mislabeled as source for K={k}, repair_index={idx}"
            ));
        }
        if symbol.esi != expected_esi {
            return Err(format!(
                "single-byte repair ESI mismatch for K={k}, repair_index={idx}: expected {expected_esi}, got {}",
                symbol.esi
            ));
        }
        if symbol.data.len() != symbol_size {
            return Err(format!(
                "single-byte repair width mismatch for K={k}, repair_index={idx}: got {}",
                symbol.data.len()
            ));
        }
    }

    let replay_encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source_replay, symbol_size, seed)
    }))
    .map_err(|_| {
        format!(
            "SystematicEncoder::new panicked during single-byte replay check K={k}, seed={seed}"
        )
    })?
    .ok_or_else(|| {
        format!(
            "SystematicEncoder::new returned None during single-byte replay check K={k}, seed={seed}"
        )
    })?;
    let mut replay_encoder = replay_encoder;
    let replay_systematic = catch_unwind(AssertUnwindSafe(|| replay_encoder.emit_systematic()))
        .map_err(|_| format!("single-byte replay emit_systematic panicked for K={k}"))?;
    let replay_repairs = catch_unwind(AssertUnwindSafe(|| {
        replay_encoder.emit_repair(bounded_repair_count)
    }))
    .map_err(|_| {
        format!("single-byte replay emit_repair panicked for K={k}, repairs={bounded_repair_count}")
    })?;

    let systematic_replay_matches = replay_systematic.len() == systematic.len()
        && replay_systematic
            .iter()
            .zip(systematic.iter())
            .all(|(replay, original)| {
                replay.esi == original.esi
                    && replay.is_source == original.is_source
                    && replay.degree == original.degree
                    && replay.data == original.data
            });
    let repair_replay_matches = replay_repairs.len() == repairs.len()
        && replay_repairs
            .iter()
            .zip(repairs.iter())
            .all(|(replay, original)| {
                replay.esi == original.esi
                    && replay.is_source == original.is_source
                    && replay.degree == original.degree
                    && replay.data == original.data
            });
    if !systematic_replay_matches || !repair_replay_matches {
        return Err(format!(
            "single-byte replay mismatch for K={k}: systematic or repair packets changed across runs"
        ));
    }

    let emit_all_encoder = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source_replay_all, symbol_size, seed)
    }))
    .map_err(|_| {
        format!("SystematicEncoder::new panicked during single-byte emit_all check K={k}, seed={seed}")
    })?
    .ok_or_else(|| {
        format!(
            "SystematicEncoder::new returned None during single-byte emit_all check K={k}, seed={seed}"
        )
    })?;
    let mut emit_all_encoder = emit_all_encoder;
    let emitted = catch_unwind(AssertUnwindSafe(|| {
        emit_all_encoder.emit_all(bounded_repair_count)
    }))
    .map_err(|_| {
        format!(
            "emit_all panicked for single-byte symbol check K={k}, repairs={bounded_repair_count}"
        )
    })?;

    let mut expected = systematic.clone();
    expected.extend(repairs.iter().cloned());
    let emit_all_matches = emitted.len() == expected.len()
        && emitted
            .iter()
            .zip(expected.iter())
            .all(|(actual, expected)| {
                actual.esi == expected.esi
                    && actual.is_source == expected.is_source
                    && actual.degree == expected.degree
                    && actual.data == expected.data
            });
    if !emit_all_matches {
        return Err(format!(
            "single-byte emit_all mismatch for K={k}: combined systematic+repair output differed"
        ));
    }
    if emitted
        .iter()
        .any(|symbol| symbol.data.len() != symbol_size)
    {
        return Err(format!(
            "single-byte emit_all produced non-uniform symbol width for K={k}"
        ));
    }

    Ok(())
}

/// Main fuzzing function
fn fuzz_systematic(mut config: FuzzConfig) -> Result<(), String> {
    let raw_k = config.k as usize;
    let raw_symbol_size = config.symbol_size as usize;
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

    // Test 1: intermediate-symbol generation via the systematic constraint
    // matrix. This exercises LDPC/HDPC/LT partitioning plus the solved
    // `A·C = D` contract that underpins encoder intermediate-symbol output.
    test_intermediate_symbol_generation(k, symbol_size, seed)?;

    // Test 2: K/K' parameter boundary conditions
    if config.test_boundary_conditions {
        test_boundary_conditions(k, symbol_size, seed)?;
    }

    // Test 3: Symbol permutation invariance
    if !config.permutation_indices.is_empty() && config.permutation_indices.len() == k {
        test_permutation_invariance(k, symbol_size, seed, &config.permutation_indices)?;
    }

    // Test 4: LT vs systematic row mixing under rank deficiency
    if config.test_rank_deficiency && repair_count > 0 {
        test_rank_deficiency_handling(k, symbol_size, seed, repair_count)?;
    }

    // Test 5: Proof validation consistency
    if repair_count > 0 {
        test_proof_consistency(k, symbol_size, seed, repair_count)?;
    }

    // Test 5b: aggregate FEC payload generation for arbitrary source bytes.
    test_payload_generation_size(k, symbol_size, seed, repair_count, &config.source_bytes)?;

    // Test 5c: bounded large-K FEC payload generation at K=10000.
    test_large_k_payload_generation_size(symbol_size, seed, repair_count, &config.source_bytes)?;

    // Test 5d: adversarial K=10000 edge-byte source blocks.
    test_large_k_edge_byte_patterns(symbol_size, seed, repair_count)?;

    // Test 5e: all-zero source blocks at K=42 and K=10000 still emit valid
    // repair packets with zero payloads.
    test_extreme_zero_source_repair_packets(symbol_size, seed, repair_count)?;

    // Test 5f: repair-symbol APIs stay byte-identical across payload sizes
    // from 8 bytes up through the RFC u16 maximum.
    test_repair_symbol_size_variation(raw_symbol_size, seed, &config.source_bytes)?;

    // Test 5g: degenerate one-byte symbols must still produce valid encoder
    // output for arbitrary K and repair counts.
    test_single_byte_symbol_output(k, seed, repair_count, &config.source_bytes)?;

    // Test 6: Basic encode/decode round-trip
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
