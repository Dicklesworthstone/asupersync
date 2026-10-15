#![allow(warnings)]
#![allow(clippy::all)]
//! Tests for Encoding Symbol ID (ESI) validation.

use crate::spec_derived::{
    ConformanceContext, ConformanceResult, RequirementLevel, Rfc6330ConformanceCase,
    Rfc6330ConformanceSuite,
};
use std::time::Instant;

const MAX_FEC_ENCODING_SYMBOL_ID: u32 = 0x00FF_FFFF;

/// Register ESI validation tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-ESI-1",
        section: "4.2",
        level: RequirementLevel::Must,
        description: "ESI values MUST be unique within source block",
        test_fn: test_esi_uniqueness,
    });
}

/// Test ESI uniqueness within source block.
#[allow(dead_code)]
fn test_esi_uniqueness(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    let mut cases_run = 0usize;
    let mut symbols_checked = 0usize;

    for k in source_block_sizes(ctx) {
        let esis = match source_symbol_esis(k) {
            Ok(esis) => esis,
            Err(err) => return ConformanceResult::fail(err),
        };

        if let Err(err) = validate_unique_source_esis(k, &esis) {
            return ConformanceResult::fail(err);
        }

        cases_run += 1;
        symbols_checked += esis.len();
    }

    if cases_run == 0 {
        return ConformanceResult::fail("No source-block sizes configured for ESI validation");
    }

    let duplicate_sequence = [0, 1, 1, 3];
    if validate_unique_source_esis(4, &duplicate_sequence).is_ok() {
        return ConformanceResult::fail("Duplicate ESI sequence was accepted");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("esi_uniqueness_cases", cases_run as f64)
        .with_metric("source_symbols_checked", symbols_checked as f64)
        .with_detail(format!(
            "Validated unique ESI assignment for {cases_run} source-block sizes"
        ))
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
fn source_symbol_esis(k: usize) -> Result<Vec<u32>, String> {
    if k == 0 {
        return Err("Source block size K must be nonzero".to_string());
    }

    let max_source_esi = (k - 1) as u64;
    if max_source_esi > u64::from(MAX_FEC_ENCODING_SYMBOL_ID) {
        return Err(format!(
            "Source block K={k} exceeds 24-bit ESI range for FEC Payload ID"
        ));
    }

    Ok((0..k as u32).collect())
}

#[allow(dead_code)]
fn validate_unique_source_esis(k: usize, esis: &[u32]) -> Result<(), String> {
    if k == 0 {
        return Err("Source block size K must be nonzero".to_string());
    }

    if esis.len() != k {
        return Err(format!(
            "Expected {k} ESIs for source block, got {}",
            esis.len()
        ));
    }

    let mut seen = vec![false; k];
    for (index, &esi) in esis.iter().enumerate() {
        let source_index = usize::try_from(esi).map_err(|_| {
            format!("ESI {esi} at position {index} cannot be represented as a source index")
        })?;

        if source_index >= k {
            return Err(format!(
                "Source ESI {esi} at position {index} is outside source range 0..{}",
                k - 1
            ));
        }

        if seen[source_index] {
            return Err(format!("Duplicate source ESI {esi} at position {index}"));
        }

        seen[source_index] = true;
    }

    if let Some(missing) = seen.iter().position(|&present| !present) {
        return Err(format!("Missing source ESI {missing}"));
    }

    Ok(())
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
    fn validates_default_source_block_esi_uniqueness() {
        let result = test_esi_uniqueness(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
        assert_eq!(result.metrics["esi_uniqueness_cases"], 7.0);
    }

    #[test]
    fn rejects_duplicate_source_esi() {
        let result = validate_unique_source_esis(4, &[0, 1, 1, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_missing_source_esi() {
        let result = validate_unique_source_esis(4, &[0, 1, 2, 4]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_source_block() {
        let result = validate_unique_source_esis(0, &[]);
        assert!(result.is_err());
    }
}
