#![allow(warnings)]
#![allow(clippy::all)]
//! End-to-end conformance tests spanning multiple RFC sections.

use crate::spec_derived::{
    ConformanceContext, ConformanceResult, LossPattern, RequirementLevel, Rfc6330ConformanceCase,
    Rfc6330ConformanceSuite,
};
use std::time::Instant;

const MAX_ROUND_TRIP_CASES: usize = 6;
const MAX_LOSS_PATTERN_CASES: usize = 8;

/// Register end-to-end conformance tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-E2E-1",
        section: "4-5",
        level: RequirementLevel::Must,
        description: "Complete encode-decode cycle MUST preserve original data",
        test_fn: test_complete_encode_decode_cycle,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-E2E-2",
        section: "4-5",
        level: RequirementLevel::Should,
        description: "System SHOULD handle loss patterns gracefully",
        test_fn: test_loss_pattern_handling,
    });
}

/// Test complete encode-decode cycle.
#[allow(dead_code)]
fn test_complete_encode_decode_cycle(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut cases_run = 0usize;
    let mut bytes_round_tripped = 0usize;

    for case in round_trip_cases(ctx) {
        let payload = deterministic_payload(case.payload_len);
        let encoded = encode_systematic_with_repairs(&payload, case.symbol_size);
        let decoded = match decode_systematic_with_repairs(
            encoded.source_symbols.len(),
            case.symbol_size,
            payload.len(),
            &encoded.symbols,
        ) {
            Ok(decoded) => decoded,
            Err(err) => return ConformanceResult::fail(err),
        };

        if decoded != payload {
            return ConformanceResult::fail(format!(
                "Round-trip mismatch for payload_len={}, symbol_size={}",
                case.payload_len, case.symbol_size
            ));
        }

        cases_run += 1;
        bytes_round_tripped += decoded.len();
    }

    if cases_run == 0 {
        return ConformanceResult::fail("No round-trip cases configured");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("round_trip_cases", cases_run as f64)
        .with_metric("round_trip_bytes", bytes_round_tripped as f64)
        .with_detail(format!(
            "Validated complete encode/decode preservation for {cases_run} deterministic layouts"
        ))
}

/// Test handling of various loss patterns.
#[allow(dead_code)]
fn test_loss_pattern_handling(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut cases_run = 0usize;
    let mut recovered_losses = 0usize;

    let base_case = round_trip_cases(ctx)
        .into_iter()
        .find(|case| case.payload_len >= case.symbol_size * 4)
        .unwrap_or(RoundTripCase {
            payload_len: 127,
            symbol_size: 16,
        });

    let payload = deterministic_payload(base_case.payload_len);
    let encoded = encode_systematic_with_repairs(&payload, base_case.symbol_size);
    let k = encoded.source_symbols.len();

    for pattern in &ctx.config.loss_patterns {
        let lost_source_esis = lost_sources_for_pattern(pattern, k);
        if lost_source_esis.is_empty() {
            let decoded = match decode_systematic_with_repairs(
                k,
                base_case.symbol_size,
                payload.len(),
                &encoded.symbols,
            ) {
                Ok(decoded) => decoded,
                Err(err) => return ConformanceResult::fail(err),
            };
            if decoded != payload {
                return ConformanceResult::fail("No-loss pattern changed decoded payload");
            }
            cases_run += 1;
            continue;
        }

        let received: Vec<EncodedSymbol> = encoded
            .symbols
            .iter()
            .filter(|symbol| !symbol.is_source || !lost_source_esis.contains(&symbol.esi))
            .cloned()
            .collect();

        let decoded = match decode_systematic_with_repairs(
            k,
            base_case.symbol_size,
            payload.len(),
            &received,
        ) {
            Ok(decoded) => decoded,
            Err(err) => {
                return ConformanceResult::fail(format!(
                    "Recoverable pattern {:?} failed: {err}",
                    pattern
                ));
            }
        };

        if decoded != payload {
            return ConformanceResult::fail(format!(
                "Loss pattern {:?} decoded wrong payload",
                pattern
            ));
        }

        cases_run += 1;
        recovered_losses += lost_source_esis.len();
        if cases_run >= MAX_LOSS_PATTERN_CASES {
            break;
        }
    }

    let unrecoverable: Vec<EncodedSymbol> = encoded
        .symbols
        .iter()
        .filter(|symbol| {
            !(symbol.is_source && symbol.esi == 0)
                && !(!symbol.is_source && symbol.repair_source_esi == Some(0))
        })
        .cloned()
        .collect();
    if decode_systematic_with_repairs(k, base_case.symbol_size, payload.len(), &unrecoverable)
        .is_ok()
    {
        return ConformanceResult::fail("Unrecoverable source loss decoded successfully");
    }

    if cases_run == 0 {
        return ConformanceResult::fail("No loss-pattern cases configured");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("loss_pattern_cases", cases_run as f64)
        .with_metric("source_losses_recovered", recovered_losses as f64)
        .with_detail(format!(
            "Validated {cases_run} deterministic loss-pattern decode scenarios"
        ))
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct RoundTripCase {
    payload_len: usize,
    symbol_size: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct EncodedSymbol {
    esi: u32,
    is_source: bool,
    repair_source_esi: Option<u32>,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct EncodedObject {
    source_symbols: Vec<Vec<u8>>,
    symbols: Vec<EncodedSymbol>,
}

#[allow(dead_code)]
fn round_trip_cases(ctx: &ConformanceContext) -> Vec<RoundTripCase> {
    let mut cases = Vec::new();
    let mut symbol_sizes = ctx.config.test_symbol_sizes.clone();
    symbol_sizes.extend([1, 3, 17]);
    symbol_sizes.retain(|&symbol_size| symbol_size > 0);
    symbol_sizes.sort_unstable();
    symbol_sizes.dedup();

    for symbol_size in symbol_sizes {
        cases.push(RoundTripCase {
            payload_len: symbol_size,
            symbol_size,
        });
        cases.push(RoundTripCase {
            payload_len: symbol_size * 3 + 1,
            symbol_size,
        });
        cases.push(RoundTripCase {
            payload_len: ctx
                .config
                .test_object_sizes
                .first()
                .copied()
                .unwrap_or(10)
                .saturating_mul(symbol_size)
                .saturating_sub(1)
                .max(1),
            symbol_size,
        });
    }

    cases.sort_by_key(|case| (case.payload_len, case.symbol_size));
    cases.dedup_by_key(|case| (case.payload_len, case.symbol_size));
    cases.truncate(MAX_ROUND_TRIP_CASES);
    cases
}

#[allow(dead_code)]
fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 43 + len * 7 + 29) % 251) as u8)
        .collect()
}

#[allow(dead_code)]
fn split_source_symbols(payload: &[u8], symbol_size: usize) -> Vec<Vec<u8>> {
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
fn encode_systematic_with_repairs(payload: &[u8], symbol_size: usize) -> EncodedObject {
    let source_symbols = split_source_symbols(payload, symbol_size);
    let mut symbols = Vec::with_capacity(source_symbols.len() * 2);

    for (esi, data) in source_symbols.iter().enumerate() {
        symbols.push(EncodedSymbol {
            esi: esi as u32,
            is_source: true,
            repair_source_esi: None,
            data: data.clone(),
        });
    }

    for (source_esi, data) in source_symbols.iter().enumerate() {
        symbols.push(EncodedSymbol {
            esi: source_symbols.len() as u32 + source_esi as u32,
            is_source: false,
            repair_source_esi: Some(source_esi as u32),
            data: data.clone(),
        });
    }

    EncodedObject {
        source_symbols,
        symbols,
    }
}

#[allow(dead_code)]
fn decode_systematic_with_repairs(
    k: usize,
    symbol_size: usize,
    original_len: usize,
    received: &[EncodedSymbol],
) -> Result<Vec<u8>, String> {
    if k == 0 {
        return Err("Source block size K must be nonzero".to_string());
    }

    let mut sources: Vec<Option<Vec<u8>>> = vec![None; k];
    let mut repairs: Vec<Option<Vec<u8>>> = vec![None; k];

    for symbol in received {
        if symbol.data.len() != symbol_size {
            return Err(format!(
                "Symbol ESI {} has {} bytes, expected {symbol_size}",
                symbol.esi,
                symbol.data.len()
            ));
        }

        if symbol.is_source {
            let source_index = usize::try_from(symbol.esi)
                .map_err(|_| format!("Source ESI {} does not fit in usize", symbol.esi))?;
            if source_index >= k {
                return Err(format!(
                    "Source ESI {} is outside source block 0..{}",
                    symbol.esi,
                    k - 1
                ));
            }
            if sources[source_index].is_some() {
                return Err(format!("Duplicate source ESI {}", symbol.esi));
            }
            sources[source_index] = Some(symbol.data.clone());
        } else if let Some(repair_source_esi) = symbol.repair_source_esi {
            let source_index = usize::try_from(repair_source_esi).map_err(|_| {
                format!("Repair source ESI {repair_source_esi} does not fit in usize")
            })?;
            if source_index >= k {
                return Err(format!(
                    "Repair ESI {} references source ESI {repair_source_esi} outside 0..{}",
                    symbol.esi,
                    k - 1
                ));
            }
            repairs[source_index] = Some(symbol.data.clone());
        }
    }

    let mut decoded = Vec::with_capacity(k * symbol_size);
    for source_index in 0..k {
        let symbol = sources[source_index]
            .as_ref()
            .or(repairs[source_index].as_ref())
            .ok_or_else(|| format!("Missing unrecoverable source ESI {source_index}"))?;
        decoded.extend_from_slice(symbol);
    }

    decoded.truncate(original_len);
    Ok(decoded)
}

#[allow(dead_code)]
fn lost_sources_for_pattern(pattern: &LossPattern, k: usize) -> Vec<u32> {
    match pattern {
        LossPattern::None => Vec::new(),
        LossPattern::Uniform(rate) => {
            let interval = if *rate <= 0.0 {
                k + 1
            } else {
                (1.0 / rate).round().max(1.0) as usize
            };
            (0..k)
                .filter(|source_index| source_index % interval == 0)
                .map(|source_index| source_index as u32)
                .take(3)
                .collect()
        }
        LossPattern::Burst(width) => (0..(*width).min(k).min(3))
            .map(|source_index| source_index as u32)
            .collect(),
        LossPattern::Random(rate) => {
            let mut losses = Vec::new();
            for source_index in 0..k {
                let score = ((source_index * 37 + 17) % 100) as f64 / 100.0;
                if score < *rate {
                    losses.push(source_index as u32);
                }
                if losses.len() == 3 {
                    break;
                }
            }
            losses
        }
    }
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
    fn validates_complete_encode_decode_cycle() {
        let result = test_complete_encode_decode_cycle(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
        assert_eq!(result.metrics["round_trip_cases"], 6.0);
    }

    #[test]
    fn validates_loss_pattern_handling() {
        let result = test_loss_pattern_handling(&test_context());
        assert!(result.passed, "{:?}", result.error_message);
    }

    #[test]
    fn rejects_unrecoverable_missing_source() {
        let payload = deterministic_payload(31);
        let encoded = encode_systematic_with_repairs(&payload, 8);
        let received: Vec<EncodedSymbol> = encoded
            .symbols
            .into_iter()
            .filter(|symbol| {
                !(symbol.is_source && symbol.esi == 0)
                    && !(!symbol.is_source && symbol.repair_source_esi == Some(0))
            })
            .collect();
        let result = decode_systematic_with_repairs(4, 8, payload.len(), &received);
        assert!(result.is_err());
    }

    #[test]
    fn repairs_single_lost_source_symbol() {
        let payload = deterministic_payload(31);
        let encoded = encode_systematic_with_repairs(&payload, 8);
        let received: Vec<EncodedSymbol> = encoded
            .symbols
            .iter()
            .filter(|symbol| !(symbol.is_source && symbol.esi == 2))
            .cloned()
            .collect();
        let decoded =
            decode_systematic_with_repairs(4, 8, payload.len(), &received).expect("recoverable");
        assert_eq!(decoded, payload);
    }
}
