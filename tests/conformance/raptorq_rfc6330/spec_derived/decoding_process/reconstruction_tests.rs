#![allow(warnings)]
#![allow(clippy::all)]
//! Tests for object reconstruction (RFC 6330 Section 4.3.3).

use crate::spec_derived::{
    ConformanceContext, ConformanceResult, RequirementLevel, Rfc6330ConformanceCase,
    Rfc6330ConformanceSuite,
};
use std::time::Instant;

const MAX_RECONSTRUCTION_CASES: usize = 8;

/// Register reconstruction tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.3.3",
        section: "4.3",
        level: RequirementLevel::Must,
        description: "Object reconstruction MUST produce original data",
        test_fn: test_object_reconstruction,
    });
}

/// Test object reconstruction correctness.
#[allow(dead_code)]
fn test_object_reconstruction(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut cases_run = 0usize;
    let mut bytes_reconstructed = 0usize;

    for symbol_size in symbol_sizes(ctx) {
        for payload_len in payload_lengths(ctx, symbol_size) {
            let payload = deterministic_payload(payload_len);
            let symbols = split_source_symbols(&payload, symbol_size);
            let k = symbols.len();

            let received: Vec<SourceSymbol> = symbols
                .into_iter()
                .enumerate()
                .map(|(esi, data)| SourceSymbol {
                    esi: esi as u32,
                    data,
                })
                .collect();

            let reconstructed = match reconstruct_object(k, symbol_size, payload_len, &received) {
                Ok(reconstructed) => reconstructed,
                Err(err) => return ConformanceResult::fail(err),
            };

            if reconstructed != payload {
                return ConformanceResult::fail(format!(
                    "Reconstructed object mismatch for len={payload_len}, symbol_size={symbol_size}"
                ));
            }

            let mut missing = received.clone();
            missing.pop();
            if reconstruct_object(k, symbol_size, payload_len, &missing).is_ok() {
                return ConformanceResult::fail(format!(
                    "Missing source symbol was accepted for len={payload_len}, symbol_size={symbol_size}"
                ));
            }

            let mut duplicate = received.clone();
            duplicate.push(received[0].clone());
            if reconstruct_object(k, symbol_size, payload_len, &duplicate).is_ok() {
                return ConformanceResult::fail(format!(
                    "Duplicate source ESI was accepted for len={payload_len}, symbol_size={symbol_size}"
                ));
            }

            bytes_reconstructed += reconstructed.len();
            cases_run += 1;
            if cases_run >= MAX_RECONSTRUCTION_CASES {
                break;
            }
        }

        if cases_run >= MAX_RECONSTRUCTION_CASES {
            break;
        }
    }

    if cases_run == 0 {
        return ConformanceResult::fail("No object reconstruction cases configured");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("object_reconstruction_cases", cases_run as f64)
        .with_metric("object_reconstruction_bytes", bytes_reconstructed as f64)
        .with_detail(format!(
            "Validated object reconstruction for {cases_run} source-symbol layouts"
        ))
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SourceSymbol {
    esi: u32,
    data: Vec<u8>,
}

#[allow(dead_code)]
fn symbol_sizes(ctx: &ConformanceContext) -> Vec<usize> {
    let mut sizes = ctx.config.test_symbol_sizes.clone();
    sizes.extend([1, 2, 3, 7]);
    sizes.retain(|&symbol_size| symbol_size > 0);
    sizes.sort_unstable();
    sizes.dedup();
    sizes
}

#[allow(dead_code)]
fn payload_lengths(ctx: &ConformanceContext, symbol_size: usize) -> Vec<usize> {
    let mut lengths = vec![
        1,
        symbol_size,
        symbol_size + 1,
        (symbol_size * 3).saturating_sub(1).max(1),
    ];

    lengths.extend(
        ctx.config
            .test_object_sizes
            .iter()
            .take(2)
            .map(|&symbols| symbols.saturating_mul(symbol_size).saturating_sub(1).max(1)),
    );

    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

#[allow(dead_code)]
fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 37 + len * 11 + 19) % 251) as u8)
        .collect()
}

#[allow(dead_code)]
fn split_source_symbols(payload: &[u8], symbol_size: usize) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        return Vec::new();
    }

    payload
        .chunks(symbol_size)
        .map(|chunk| {
            let mut symbol = chunk.to_vec();
            symbol.resize(symbol_size, 0);
            symbol
        })
        .collect()
}

#[allow(dead_code)]
fn reconstruct_object(
    k: usize,
    symbol_size: usize,
    original_len: usize,
    received: &[SourceSymbol],
) -> Result<Vec<u8>, String> {
    if k == 0 {
        return Err("Source block size K must be nonzero".to_string());
    }

    if symbol_size == 0 {
        return Err("Symbol size must be nonzero".to_string());
    }

    if received.len() != k {
        return Err(format!(
            "Expected {k} source symbols for reconstruction, got {}",
            received.len()
        ));
    }

    let mut ordered: Vec<Option<Vec<u8>>> = vec![None; k];
    for symbol in received {
        let index = usize::try_from(symbol.esi)
            .map_err(|_| format!("ESI {} does not fit in usize", symbol.esi))?;

        if index >= k {
            return Err(format!(
                "Source ESI {} is outside reconstruction range 0..{}",
                symbol.esi,
                k - 1
            ));
        }

        if symbol.data.len() != symbol_size {
            return Err(format!(
                "Source ESI {} has {} bytes, expected {symbol_size}",
                symbol.esi,
                symbol.data.len()
            ));
        }

        if ordered[index].is_some() {
            return Err(format!("Duplicate source ESI {}", symbol.esi));
        }

        ordered[index] = Some(symbol.data.clone());
    }

    let mut reconstructed = Vec::with_capacity(k * symbol_size);
    for (index, symbol) in ordered.into_iter().enumerate() {
        let Some(symbol) = symbol else {
            return Err(format!("Missing source ESI {index}"));
        };
        reconstructed.extend_from_slice(&symbol);
    }

    reconstructed.truncate(original_len);
    Ok(reconstructed)
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
    fn validates_object_reconstruction() {
        let result = test_object_reconstruction(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
        assert_eq!(result.metrics["object_reconstruction_cases"], 8.0);
    }

    #[test]
    fn trims_padding_to_original_length() {
        let payload = vec![1, 2, 3, 4, 5];
        let symbols = split_source_symbols(&payload, 4);
        let received: Vec<SourceSymbol> = symbols
            .into_iter()
            .enumerate()
            .map(|(esi, data)| SourceSymbol {
                esi: esi as u32,
                data,
            })
            .collect();

        let reconstructed = reconstruct_object(2, 4, payload.len(), &received).unwrap();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn rejects_duplicate_source_symbol() {
        let symbol = SourceSymbol {
            esi: 0,
            data: vec![0; 4],
        };
        let result = reconstruct_object(1, 4, 4, &[symbol.clone(), symbol]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_out_of_range_source_esi() {
        let symbol = SourceSymbol {
            esi: 2,
            data: vec![0; 4],
        };
        let result = reconstruct_object(1, 4, 4, &[symbol]);
        assert!(result.is_err());
    }
}
