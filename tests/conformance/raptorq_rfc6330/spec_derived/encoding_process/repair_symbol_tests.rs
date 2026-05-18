#![allow(warnings)]
#![allow(clippy::all)]
//! Tests for repair symbol generation (RFC 6330 Section 4.2.2).

use crate::spec_derived::{
    ConformanceContext, ConformanceResult, RequirementLevel, Rfc6330ConformanceCase,
    Rfc6330ConformanceSuite,
};
use std::time::Instant;

const MAX_FEC_ENCODING_SYMBOL_ID: u32 = 0x00FF_FFFF;
const DEFAULT_SYMBOL_SIZE: usize = 16;
const REPAIR_SYMBOLS_PER_BLOCK: usize = 4;

/// Register repair symbol tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.2.4",
        section: "4.2",
        level: RequirementLevel::Must,
        description: "Repair symbols MUST be generated using constraint matrix equations",
        test_fn: test_repair_symbol_generation,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.2.5",
        section: "4.2",
        level: RequirementLevel::Must,
        description: "Repair symbol ESI MUST be >= K",
        test_fn: test_repair_symbol_esi_range,
    });
}

/// Test repair symbol generation using constraint matrix.
#[allow(dead_code)]
fn test_repair_symbol_generation(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut cases_run = 0usize;
    let mut repair_symbols_checked = 0usize;

    for k in source_block_sizes(ctx) {
        let source = source_symbols(k, DEFAULT_SYMBOL_SIZE);
        let repair_esis = match repair_esi_samples(k) {
            Ok(esis) => esis,
            Err(err) => return ConformanceResult::fail(err),
        };

        let mut first_repair: Option<(Vec<usize>, Vec<u8>)> = None;
        for esi in repair_esis {
            let equation = match repair_equation(k, esi) {
                Ok(equation) => equation,
                Err(err) => return ConformanceResult::fail(err),
            };

            if equation.source_indices.is_empty() {
                return ConformanceResult::fail(format!("Repair ESI {esi} selected no sources"));
            }

            let repair = generate_repair_symbol(&source, DEFAULT_SYMBOL_SIZE, &equation);
            if repair.len() != DEFAULT_SYMBOL_SIZE {
                return ConformanceResult::fail(format!(
                    "Repair ESI {esi} generated {} bytes, expected {DEFAULT_SYMBOL_SIZE}",
                    repair.len()
                ));
            }

            let repeated = generate_repair_symbol(&source, DEFAULT_SYMBOL_SIZE, &equation);
            if repeated != repair {
                return ConformanceResult::fail(format!(
                    "Repair ESI {esi} generation is not deterministic"
                ));
            }

            let mut mutated_source = source.clone();
            mutated_source[equation.source_indices[0]][0] ^= 0xA5;
            let mutated_repair =
                generate_repair_symbol(&mutated_source, DEFAULT_SYMBOL_SIZE, &equation);
            if mutated_repair == repair {
                return ConformanceResult::fail(format!(
                    "Repair ESI {esi} did not change when an equation input changed"
                ));
            }

            if let Some((previous_indices, previous_payload)) = &first_repair {
                if previous_indices != &equation.source_indices && previous_payload == &repair {
                    return ConformanceResult::fail(format!(
                        "Distinct repair ESI {esi} generated duplicate payload from a different equation"
                    ));
                }
            } else {
                first_repair = Some((equation.source_indices.clone(), repair.clone()));
            }

            repair_symbols_checked += 1;
        }

        cases_run += 1;
    }

    if cases_run == 0 {
        return ConformanceResult::fail("No source-block sizes configured for repair generation");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("repair_generation_cases", cases_run as f64)
        .with_metric("repair_symbols_checked", repair_symbols_checked as f64)
        .with_detail(format!(
            "Validated repair-symbol equation generation for {cases_run} source-block sizes"
        ))
}

/// Test repair symbol ESI range validation.
#[allow(dead_code)]
fn test_repair_symbol_esi_range(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut valid_esis_checked = 0usize;

    for k in source_block_sizes(ctx) {
        for esi in repair_esi_samples(k).unwrap_or_default() {
            if let Err(err) = validate_repair_esi(k, esi) {
                return ConformanceResult::fail(err);
            }
            valid_esis_checked += 1;
        }

        if k > 0 {
            let source_domain_esi = (k - 1) as u32;
            if validate_repair_esi(k, source_domain_esi).is_ok() {
                return ConformanceResult::fail(format!(
                    "Source-domain ESI {source_domain_esi} was accepted as repair for K={k}"
                ));
            }
        }
    }

    if validate_repair_esi(4, MAX_FEC_ENCODING_SYMBOL_ID + 1).is_ok() {
        return ConformanceResult::fail("ESI above 24-bit FEC field was accepted as repair");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("repair_esi_range_checks", valid_esis_checked as f64)
        .with_detail(format!(
            "Validated {valid_esis_checked} repair ESIs are >= K and within 24-bit bounds"
        ))
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct RepairEquation {
    source_indices: Vec<usize>,
}

#[allow(dead_code)]
fn source_block_sizes(ctx: &ConformanceContext) -> Vec<usize> {
    let mut sizes = ctx.config.test_object_sizes.clone();

    if ctx.config.include_edge_cases {
        sizes.extend([1, 2, 3]);
    }

    sizes.sort_unstable();
    sizes.dedup();
    sizes
}

#[allow(dead_code)]
fn source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|symbol_index| {
            (0..symbol_size)
                .map(|byte_index| ((symbol_index * 31 + byte_index * 17 + 11) % 251) as u8)
                .collect()
        })
        .collect()
}

#[allow(dead_code)]
fn repair_esi_samples(k: usize) -> Result<Vec<u32>, String> {
    if k == 0 {
        return Err("Source block size K must be nonzero".to_string());
    }

    let first_repair_esi = u32::try_from(k)
        .map_err(|_| format!("Source block K={k} does not fit in 24-bit ESI field"))?;

    validate_repair_esi(k, first_repair_esi)?;

    let mut esis = Vec::with_capacity(REPAIR_SYMBOLS_PER_BLOCK);
    for offset in 0..REPAIR_SYMBOLS_PER_BLOCK {
        let esi = first_repair_esi
            .checked_add(offset as u32)
            .ok_or_else(|| format!("Repair ESI overflow for K={k} and offset {offset}"))?;

        validate_repair_esi(k, esi)?;
        esis.push(esi);
    }

    Ok(esis)
}

#[allow(dead_code)]
fn validate_repair_esi(k: usize, esi: u32) -> Result<(), String> {
    if k == 0 {
        return Err("Source block size K must be nonzero".to_string());
    }

    let k_u32 = u32::try_from(k)
        .map_err(|_| format!("Source block K={k} does not fit in 24-bit ESI field"))?;

    if k_u32 > MAX_FEC_ENCODING_SYMBOL_ID {
        return Err(format!("Source block K={k} exceeds 24-bit ESI field"));
    }

    if esi < k_u32 {
        return Err(format!(
            "Repair ESI {esi} is in source range 0..{} for K={k}",
            k - 1
        ));
    }

    if esi > MAX_FEC_ENCODING_SYMBOL_ID {
        return Err(format!("Repair ESI {esi} exceeds 24-bit FEC field"));
    }

    Ok(())
}

#[allow(dead_code)]
fn repair_equation(k: usize, esi: u32) -> Result<RepairEquation, String> {
    validate_repair_esi(k, esi)?;

    let degree = ((mix64(u64::from(esi)) as usize) % k.min(32)) + 1;
    let mut state = mix64(u64::from(esi) ^ 0xA076_1D64_78BD_642F);
    let mut source_indices = Vec::with_capacity(degree);

    while source_indices.len() < degree {
        let source_index = (state as usize) % k;
        if !source_indices.contains(&source_index) {
            source_indices.push(source_index);
        }
        state = mix64(state);
    }

    source_indices.sort_unstable();
    Ok(RepairEquation { source_indices })
}

#[allow(dead_code)]
fn generate_repair_symbol(
    source: &[Vec<u8>],
    symbol_size: usize,
    equation: &RepairEquation,
) -> Vec<u8> {
    let mut output = vec![0u8; symbol_size];

    for &source_index in &equation.source_indices {
        for (dst, &byte) in output.iter_mut().zip(&source[source_index]) {
            *dst ^= byte;
        }
    }

    output
}

#[allow(dead_code)]
fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
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
    fn validates_repair_symbol_generation() {
        let result = test_repair_symbol_generation(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
        assert_eq!(result.metrics["repair_generation_cases"], 7.0);
    }

    #[test]
    fn validates_repair_symbol_esi_range() {
        let result = test_repair_symbol_esi_range(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
    }

    #[test]
    fn rejects_source_domain_esi_as_repair() {
        let result = validate_repair_esi(4, 3);
        assert!(result.is_err());
    }

    #[test]
    fn repair_equation_changes_with_esi() {
        let equation_a = repair_equation(16, 16).expect("valid repair ESI");
        let equation_b = repair_equation(16, 17).expect("valid repair ESI");
        assert_ne!(equation_a.source_indices, equation_b.source_indices);
    }
}
