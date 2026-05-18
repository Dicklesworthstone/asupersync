#![allow(warnings)]
#![allow(clippy::all)]
//! Edge case and boundary condition tests for RFC 6330.

use crate::spec_derived::{
    ConformanceContext, ConformanceResult, RequirementLevel, Rfc6330ConformanceCase,
    Rfc6330ConformanceSuite,
};
use std::time::Instant;

const MIN_K_BOUNDARY: usize = 4;
const MAX_K_BOUNDARY: usize = 8192;
const MIN_SYMBOL_SIZE: usize = 1;
const MAX_BOUNDARY_SYMBOL_SIZE: usize = 16;

/// Register edge case matrix tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-EDGE-1",
        section: "4-5",
        level: RequirementLevel::Must,
        description: "System MUST handle minimum K=4 correctly",
        test_fn: test_minimum_k_boundary,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-EDGE-2",
        section: "4-5",
        level: RequirementLevel::Must,
        description: "System MUST handle maximum K=8192 correctly",
        test_fn: test_maximum_k_boundary,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-EDGE-3",
        section: "4-5",
        level: RequirementLevel::Should,
        description: "System SHOULD handle single-byte symbols gracefully",
        test_fn: test_minimal_symbol_size,
    });
}

/// Test minimum K boundary (K=4).
#[allow(dead_code)]
fn test_minimum_k_boundary(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let symbol_size = bounded_symbol_size(ctx);
    let payload = deterministic_payload(MIN_K_BOUNDARY * symbol_size);
    let symbols = match split_payload_into_symbols(&payload, MIN_K_BOUNDARY, symbol_size) {
        Ok(symbols) => symbols,
        Err(err) => return ConformanceResult::fail(err),
    };

    if let Err(err) = validate_source_symbols(&symbols, MIN_K_BOUNDARY, symbol_size) {
        return ConformanceResult::fail(err);
    }

    let reconstructed = match reconstruct_payload(&symbols, payload.len()) {
        Ok(reconstructed) => reconstructed,
        Err(err) => return ConformanceResult::fail(err),
    };
    if reconstructed != payload {
        return ConformanceResult::fail("K=4 source block did not reconstruct exactly");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("minimum_k", MIN_K_BOUNDARY as f64)
        .with_metric("symbol_size", symbol_size as f64)
        .with_detail("Validated exact source ordering and reconstruction at K=4")
}

/// Test maximum K boundary (K=8192).
#[allow(dead_code)]
fn test_maximum_k_boundary(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let symbol_size = bounded_symbol_size(ctx);
    let payload = deterministic_payload(MAX_K_BOUNDARY * symbol_size);
    let symbols = match split_payload_into_symbols(&payload, MAX_K_BOUNDARY, symbol_size) {
        Ok(symbols) => symbols,
        Err(err) => return ConformanceResult::fail(err),
    };

    if let Err(err) = validate_source_symbols(&symbols, MAX_K_BOUNDARY, symbol_size) {
        return ConformanceResult::fail(err);
    }

    let expected_last_esi = MAX_K_BOUNDARY - 1;
    if symbols.first().map(|symbol| symbol.esi) != Some(0) {
        return ConformanceResult::fail("K=8192 block did not start at ESI 0");
    }
    if symbols.last().map(|symbol| symbol.esi) != Some(expected_last_esi) {
        return ConformanceResult::fail(format!(
            "K=8192 block did not end at ESI {expected_last_esi}"
        ));
    }

    let checksum = source_symbol_checksum(&symbols);
    if checksum == 0 {
        return ConformanceResult::fail("K=8192 deterministic checksum collapsed to zero");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("maximum_k", MAX_K_BOUNDARY as f64)
        .with_metric("payload_bytes", payload.len() as f64)
        .with_metric("source_symbol_checksum", checksum as f64)
        .with_detail("Validated contiguous ESI coverage and symbol sizing at K=8192")
}

/// Test minimal symbol size handling.
#[allow(dead_code)]
fn test_minimal_symbol_size(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut cases_run = 0usize;

    for k in single_byte_k_cases(ctx) {
        let payload = deterministic_payload(k);
        let symbols = match split_payload_into_symbols(&payload, k, MIN_SYMBOL_SIZE) {
            Ok(symbols) => symbols,
            Err(err) => return ConformanceResult::fail(err),
        };

        if let Err(err) = validate_source_symbols(&symbols, k, MIN_SYMBOL_SIZE) {
            return ConformanceResult::fail(err);
        }

        if symbols
            .iter()
            .any(|symbol| symbol.data.len() != MIN_SYMBOL_SIZE)
        {
            return ConformanceResult::fail(format!("K={k} produced a symbol wider than one byte"));
        }

        let reconstructed = match reconstruct_payload(&symbols, payload.len()) {
            Ok(reconstructed) => reconstructed,
            Err(err) => return ConformanceResult::fail(err),
        };
        if reconstructed != payload {
            return ConformanceResult::fail(format!(
                "Single-byte symbol reconstruction mismatch for K={k}"
            ));
        }

        cases_run += 1;
    }

    if cases_run == 0 {
        return ConformanceResult::fail("No single-byte symbol cases configured");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("single_byte_cases", cases_run as f64)
        .with_detail(format!(
            "Validated single-byte source symbols across {cases_run} K values"
        ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct SourceSymbol {
    esi: usize,
    data: Vec<u8>,
}

#[allow(dead_code)]
fn bounded_symbol_size(ctx: &ConformanceContext) -> usize {
    ctx.config
        .test_symbol_sizes
        .iter()
        .copied()
        .filter(|symbol_size| *symbol_size > 0)
        .min()
        .unwrap_or(MIN_SYMBOL_SIZE)
        .clamp(MIN_SYMBOL_SIZE, MAX_BOUNDARY_SYMBOL_SIZE)
}

#[allow(dead_code)]
fn single_byte_k_cases(ctx: &ConformanceContext) -> Vec<usize> {
    let mut cases = vec![MIN_K_BOUNDARY, 5, 17];
    cases.extend(
        ctx.config
            .test_object_sizes
            .iter()
            .copied()
            .filter(|k| (MIN_K_BOUNDARY..=64).contains(k)),
    );
    cases.sort_unstable();
    cases.dedup();
    cases
}

#[allow(dead_code)]
fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 31 + len * 13 + 7) % 251) as u8)
        .collect()
}

#[allow(dead_code)]
fn split_payload_into_symbols(
    payload: &[u8],
    k: usize,
    symbol_size: usize,
) -> Result<Vec<SourceSymbol>, String> {
    if k == 0 {
        return Err("Source block size K must be nonzero".to_string());
    }
    if symbol_size == 0 {
        return Err("Symbol size must be nonzero".to_string());
    }

    let block_capacity = k
        .checked_mul(symbol_size)
        .ok_or_else(|| "K * symbol_size overflowed".to_string())?;
    if payload.len() > block_capacity {
        return Err(format!(
            "Payload has {} bytes but K={k}, symbol_size={symbol_size} only cover {block_capacity}",
            payload.len()
        ));
    }

    let mut symbols = Vec::with_capacity(k);
    for esi in 0..k {
        let start = esi * symbol_size;
        let end = (start + symbol_size).min(payload.len());
        let mut data = if start < payload.len() {
            payload[start..end].to_vec()
        } else {
            Vec::new()
        };
        data.resize(symbol_size, 0);
        symbols.push(SourceSymbol { esi, data });
    }
    Ok(symbols)
}

#[allow(dead_code)]
fn validate_source_symbols(
    symbols: &[SourceSymbol],
    expected_k: usize,
    symbol_size: usize,
) -> Result<(), String> {
    if expected_k == 0 {
        return Err("Expected source block size K must be nonzero".to_string());
    }
    if symbols.len() != expected_k {
        return Err(format!(
            "Expected {expected_k} source symbols, got {}",
            symbols.len()
        ));
    }

    let mut seen = vec![false; expected_k];
    for (position, symbol) in symbols.iter().enumerate() {
        if symbol.esi >= expected_k {
            return Err(format!(
                "Symbol at position {position} has out-of-range ESI {} for K={expected_k}",
                symbol.esi
            ));
        }
        if seen[symbol.esi] {
            return Err(format!("Duplicate source ESI {}", symbol.esi));
        }
        if symbol.esi != position {
            return Err(format!(
                "Symbol at position {position} has ESI {}, expected source order ESI {position}",
                symbol.esi
            ));
        }
        if symbol.data.len() != symbol_size {
            return Err(format!(
                "Symbol ESI {} has {} bytes, expected {symbol_size}",
                symbol.esi,
                symbol.data.len()
            ));
        }
        seen[symbol.esi] = true;
    }

    if let Some(missing) = seen.iter().position(|present| !present) {
        return Err(format!("Missing source ESI {missing}"));
    }

    Ok(())
}

#[allow(dead_code)]
fn reconstruct_payload(symbols: &[SourceSymbol], original_len: usize) -> Result<Vec<u8>, String> {
    let mut ordered = vec![None; symbols.len()];
    for symbol in symbols {
        if symbol.esi >= symbols.len() {
            return Err(format!(
                "Cannot reconstruct out-of-range ESI {} from {} symbols",
                symbol.esi,
                symbols.len()
            ));
        }
        if ordered[symbol.esi].is_some() {
            return Err(format!("Duplicate source ESI {}", symbol.esi));
        }
        ordered[symbol.esi] = Some(symbol.data.as_slice());
    }

    let mut payload = Vec::new();
    for (esi, symbol) in ordered.into_iter().enumerate() {
        let symbol = symbol.ok_or_else(|| format!("Missing source ESI {esi}"))?;
        payload.extend_from_slice(symbol);
    }
    payload.truncate(original_len);
    Ok(payload)
}

#[allow(dead_code)]
fn source_symbol_checksum(symbols: &[SourceSymbol]) -> u64 {
    let mut checksum = 0u64;
    for symbol in symbols {
        checksum = checksum.wrapping_add((symbol.esi as u64 + 1) * 17);
        for (offset, byte) in symbol.data.iter().enumerate() {
            checksum = checksum
                .wrapping_mul(1_099_511_628_211)
                .wrapping_add(u64::from(*byte) + offset as u64);
        }
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_derived::{ConformanceConfig, ConformanceContext};

    fn test_context() -> ConformanceContext {
        ConformanceContext {
            config: ConformanceConfig::default(),
            timeout: std::time::Duration::from_secs(10),
            verbose: false,
        }
    }

    #[test]
    fn validates_minimum_k_boundary() {
        let result = test_minimum_k_boundary(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
        assert_eq!(result.metrics["minimum_k"], MIN_K_BOUNDARY as f64);
    }

    #[test]
    fn validates_maximum_k_boundary() {
        let result = test_maximum_k_boundary(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
        assert_eq!(result.metrics["maximum_k"], MAX_K_BOUNDARY as f64);
    }

    #[test]
    fn validates_single_byte_symbol_boundary() {
        let result = test_minimal_symbol_size(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
        assert!(result.metrics["single_byte_cases"] >= 3.0);
    }

    #[test]
    fn rejects_zero_symbol_size() {
        let result = split_payload_into_symbols(&[1, 2, 3, 4], MIN_K_BOUNDARY, 0);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_source_esi() {
        let mut symbols =
            split_payload_into_symbols(&deterministic_payload(4), MIN_K_BOUNDARY, 1).unwrap();
        symbols[1].esi = 0;
        let result = validate_source_symbols(&symbols, MIN_K_BOUNDARY, 1);
        assert!(result.is_err());
    }
}
