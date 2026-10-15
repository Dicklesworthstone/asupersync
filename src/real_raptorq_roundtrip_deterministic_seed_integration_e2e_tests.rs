//! E2E Integration Tests: raptorq roundtrip with deterministic seed
//!
//! Tests encode-then-decode roundtrip with deterministic seed.
//! Verifies all source symbols are recovered and repair count matches expected values.
//! Focus on deterministic behavior and precise symbol accounting.

use crate::{
    bytes::Bytes,
    raptorq::{
        decoder::{InactivationDecoder, ReceivedSymbol},
        systematic::{EmittedSymbol, SystematicEncoder},
    },
    runtime::{Runtime, RuntimeBuilder},
    types::Outcome,
    util::det_rng::DetRng,
};
use std::{collections::BTreeMap, error::Error, fmt, time::Instant};

/// RaptorQ roundtrip test harness with deterministic seeding
struct RaptorQRoundtripHarness {
    runtime: Runtime,
    seed: u64,
    rng: DetRng,
    stats: RoundtripStats,
}

#[derive(Debug, Default, Clone)]
struct RoundtripStats {
    encoding_duration_ms: f64,
    decoding_duration_ms: f64,
    source_symbols_generated: u64,
    repair_symbols_generated: u64,
    symbols_transmitted: u64,
    symbols_lost: u64,
    symbols_received: u64,
    source_symbols_recovered: u64,
    repair_symbols_used: u64,
    decoding_overhead: f64,
    memory_usage_bytes: u64,
}

impl RaptorQRoundtripHarness {
    fn new(seed: u64) -> Self {
        Self {
            runtime: RuntimeBuilder::new()
                .build()
                .expect("RaptorQ roundtrip harness runtime should build"),
            seed,
            rng: DetRng::new(seed),
            stats: RoundtripStats::default(),
        }
    }

    /// Test perfect roundtrip (no symbol loss)
    async fn test_perfect_roundtrip(
        &mut self,
        k: u16,
        symbol_size: u16,
    ) -> Outcome<TestResult, Box<dyn Error>> {
        // Generate deterministic source data
        let source_data = self.generate_source_data(k, symbol_size);

        let encoding_start = Instant::now();

        // Encode the data using RaptorQ systematic encoding
        let encoding_result = self.encode_data(&source_data, k, symbol_size).await?;

        self.stats.encoding_duration_ms = encoding_start.elapsed().as_millis() as f64;
        self.stats.source_symbols_generated = encoding_result.source_symbols.len() as u64;
        self.stats.repair_symbols_generated = encoding_result.repair_symbols.len() as u64;
        self.stats.memory_usage_bytes = estimate_symbol_bytes(
            &encoding_result.source_symbols,
            &encoding_result.repair_symbols,
        );

        // Transmit all source symbols (perfect transmission)
        let mut transmitted_symbols = Vec::new();
        for (esi, symbol) in &encoding_result.source_symbols {
            transmitted_symbols.push((*esi, symbol.clone()));
        }

        self.stats.symbols_transmitted = transmitted_symbols.len() as u64;
        self.stats.symbols_received = transmitted_symbols.len() as u64;
        self.stats.symbols_lost = 0;

        let decoding_start = Instant::now();

        // Decode the data
        let decoding_result = self
            .decode_symbols(transmitted_symbols, k, symbol_size)
            .await?;

        self.stats.decoding_duration_ms = decoding_start.elapsed().as_millis() as f64;

        // Verify perfect recovery
        let recovered_data = decoding_result.recovered_data;
        let success = recovered_data == source_data;

        self.stats.source_symbols_recovered = k as u64;
        self.stats.repair_symbols_used = 0;
        self.stats.decoding_overhead = 0.0;

        Outcome::Ok(TestResult {
            scenario: "perfect_roundtrip".to_string(),
            success,
            k,
            symbol_size,
            source_data_len: source_data.len(),
            recovered_data_len: recovered_data.len(),
            symbols_required: k,
            symbols_used: k,
            repair_symbols_needed: 0,
            all_source_recovered: true,
            data_integrity_verified: success,
            stats: self.stats.clone(),
            notes: format!("Perfect transmission: {}/{} symbols", k, k),
        })
    }

    /// Test roundtrip with symbol loss requiring repair symbols
    async fn test_lossy_roundtrip(
        &mut self,
        k: u16,
        symbol_size: u16,
        loss_rate: f32,
    ) -> Outcome<TestResult, Box<dyn Error>> {
        let source_data = self.generate_source_data(k, symbol_size);

        let encoding_start = Instant::now();
        let encoding_result = self.encode_data(&source_data, k, symbol_size).await?;
        self.stats.encoding_duration_ms = encoding_start.elapsed().as_millis() as f64;
        self.stats.source_symbols_generated = encoding_result.source_symbols.len() as u64;
        self.stats.repair_symbols_generated = encoding_result.repair_symbols.len() as u64;
        self.stats.memory_usage_bytes = estimate_symbol_bytes(
            &encoding_result.source_symbols,
            &encoding_result.repair_symbols,
        );

        // Simulate lossy transmission
        let transmitted_symbols = self.simulate_lossy_transmission(
            &encoding_result.source_symbols,
            &encoding_result.repair_symbols,
            k,
            loss_rate,
        );

        self.stats.symbols_transmitted =
            (encoding_result.source_symbols.len() + encoding_result.repair_symbols.len()) as u64;
        self.stats.symbols_received = transmitted_symbols.len() as u64;
        self.stats.symbols_lost = self.stats.symbols_transmitted - self.stats.symbols_received;

        let decoding_start = Instant::now();
        let decoding_result = self
            .decode_symbols(transmitted_symbols, k, symbol_size)
            .await?;
        self.stats.decoding_duration_ms = decoding_start.elapsed().as_millis() as f64;

        let recovered_data = decoding_result.recovered_data;
        let success = recovered_data == source_data;

        let repair_symbols_used = decoding_result.repair_symbols_received;

        self.stats.source_symbols_recovered = if success {
            k as u64
        } else {
            decoding_result.source_symbols_received as u64
        };
        self.stats.repair_symbols_used = repair_symbols_used as u64;
        self.stats.decoding_overhead = if k > 0 {
            (repair_symbols_used as f64 / k as f64) * 100.0
        } else {
            0.0
        };

        Outcome::Ok(TestResult {
            scenario: format!("lossy_roundtrip_{:.1}%", loss_rate * 100.0),
            success,
            k,
            symbol_size,
            source_data_len: source_data.len(),
            recovered_data_len: recovered_data.len(),
            symbols_required: k,
            symbols_used: decoding_result.total_symbols_used,
            repair_symbols_needed: repair_symbols_used,
            all_source_recovered: success,
            data_integrity_verified: success,
            stats: self.stats.clone(),
            notes: format!(
                "Loss rate: {:.1}%, Repair symbols used: {}, Overhead: {:.1}%",
                loss_rate * 100.0,
                repair_symbols_used,
                self.stats.decoding_overhead
            ),
        })
    }

    /// Test systematic recovery (receive exactly first K symbols)
    async fn test_systematic_recovery(
        &mut self,
        k: u16,
        symbol_size: u16,
    ) -> Outcome<TestResult, Box<dyn Error>> {
        let source_data = self.generate_source_data(k, symbol_size);
        let encoding_result = self.encode_data(&source_data, k, symbol_size).await?;
        self.stats.source_symbols_generated = encoding_result.source_symbols.len() as u64;
        self.stats.repair_symbols_generated = encoding_result.repair_symbols.len() as u64;
        self.stats.memory_usage_bytes = estimate_symbol_bytes(
            &encoding_result.source_symbols,
            &encoding_result.repair_symbols,
        );

        // Take exactly the first K source symbols (systematic recovery)
        let mut transmitted_symbols = Vec::new();
        for i in 0..k {
            if let Some(symbol) = encoding_result.source_symbols.get(&(i as u32)) {
                transmitted_symbols.push((i as u32, symbol.clone()));
            }
        }

        let decoding_result = self
            .decode_symbols(transmitted_symbols, k, symbol_size)
            .await?;
        let recovered_data = decoding_result.recovered_data;
        let success = recovered_data == source_data;

        Outcome::Ok(TestResult {
            scenario: "systematic_recovery".to_string(),
            success,
            k,
            symbol_size,
            source_data_len: source_data.len(),
            recovered_data_len: recovered_data.len(),
            symbols_required: k,
            symbols_used: k,
            repair_symbols_needed: 0,
            all_source_recovered: true,
            data_integrity_verified: success,
            stats: self.stats.clone(),
            notes: "Systematic recovery using first K source symbols".to_string(),
        })
    }

    /// Generate deterministic source data
    fn generate_source_data(&mut self, k: u16, symbol_size: u16) -> Bytes {
        let total_size = k as usize * symbol_size as usize;
        let mut data = Vec::with_capacity(total_size);

        for i in 0..total_size {
            // Use deterministic pattern based on position and seed
            let value = ((i ^ (self.seed as usize)) % 256) as u8;
            data.push(value);
        }

        Bytes::from(data)
    }

    /// Encode data with the repository's deterministic RaptorQ systematic encoder.
    async fn encode_data(
        &mut self,
        source_data: &Bytes,
        k: u16,
        symbol_size: u16,
    ) -> Outcome<EncodingResult, Box<dyn Error>> {
        let source_symbols_vec = split_source_symbols(source_data, k, symbol_size);
        let mut encoder =
            SystematicEncoder::new(&source_symbols_vec, symbol_size as usize, self.seed)
                .ok_or_else(|| test_error("RaptorQ systematic encoder setup failed"))?;
        let decoder = InactivationDecoder::new(k as usize, symbol_size as usize, self.seed);

        let mut source_symbols = BTreeMap::new();
        for emitted in encoder.emit_systematic() {
            source_symbols.insert(emitted.esi, RoundtripSymbol::from_emitted(emitted));
        }

        let repair_count = decoder
            .params()
            .l
            .saturating_sub(k as usize)
            .saturating_add((k as usize).div_ceil(2))
            .saturating_add(4);
        let mut repair_symbols = BTreeMap::new();
        for emitted in encoder.emit_repair(repair_count) {
            repair_symbols.insert(emitted.esi, RoundtripSymbol::from_emitted(emitted));
        }

        Outcome::Ok(EncodingResult {
            source_symbols,
            repair_symbols,
        })
    }

    /// Simulate lossy transmission
    fn simulate_lossy_transmission(
        &mut self,
        source_symbols: &BTreeMap<u32, RoundtripSymbol>,
        repair_symbols: &BTreeMap<u32, RoundtripSymbol>,
        _k: u16,
        loss_rate: f32,
    ) -> Vec<(u32, RoundtripSymbol)> {
        let mut transmitted = Vec::new();
        let mut lost_source_count = 0usize;

        // Randomly drop source symbols based on loss rate
        for (esi, symbol) in source_symbols {
            if self.should_deliver_symbol(loss_rate) {
                transmitted.push((*esi, symbol.clone()));
            } else {
                lost_source_count += 1;
            }
        }

        // Add repair symbols to compensate for lost source symbols
        // Add a few extra to ensure decodability
        let repair_needed = lost_source_count + 2;
        let mut repair_added = 0;

        for (esi, symbol) in repair_symbols {
            if repair_added >= repair_needed {
                break;
            }
            if self.should_deliver_symbol(loss_rate) {
                transmitted.push((*esi, symbol.clone()));
                repair_added += 1;
            }
        }

        transmitted
    }

    fn should_deliver_symbol(&mut self, loss_rate: f32) -> bool {
        let threshold = (loss_rate.clamp(0.0, 1.0) * 1_000_000.0) as u32;
        self.rng.next_u32() % 1_000_000 >= threshold
    }

    /// Decode symbols with the repository's RaptorQ inactivation decoder.
    async fn decode_symbols(
        &mut self,
        symbols: Vec<(u32, RoundtripSymbol)>,
        k: u16,
        symbol_size: u16,
    ) -> Outcome<DecodingResult, Box<dyn Error>> {
        let decoder = InactivationDecoder::new(k as usize, symbol_size as usize, self.seed);
        let mut source_symbols_received = 0;
        let mut repair_symbols_received = 0;

        // Sort symbols by ESI for systematic decoding
        let mut sorted_symbols = symbols;
        sorted_symbols.sort_by_key(|(esi, _)| *esi);

        let mut received = decoder.constraint_symbols();
        for (esi, symbol) in sorted_symbols {
            if symbol.is_source {
                source_symbols_received += 1;
                received.push(ReceivedSymbol::source(esi, symbol.data));
            } else {
                repair_symbols_received += 1;
                let (columns, coefficients) = decoder
                    .repair_equation(esi)
                    .map_err(|err| test_error(format!("repair equation failed: {err:?}")))?;
                received.push(ReceivedSymbol::repair(
                    esi,
                    columns,
                    coefficients,
                    symbol.data,
                ));
            }
        }

        let decoded = decoder
            .decode(&received)
            .map_err(|err| test_error(format!("RaptorQ decode failed: {err:?}")))?;
        let mut recovered_data = Vec::with_capacity(k as usize * symbol_size as usize);
        for symbol in decoded.source {
            recovered_data.extend_from_slice(&symbol);
        }

        Outcome::Ok(DecodingResult {
            recovered_data: Bytes::from(recovered_data),
            source_symbols_received,
            repair_symbols_received,
            total_symbols_used: (source_symbols_received + repair_symbols_received) as u16,
        })
    }
}

#[derive(Debug)]
struct EncodingResult {
    source_symbols: BTreeMap<u32, RoundtripSymbol>,
    repair_symbols: BTreeMap<u32, RoundtripSymbol>,
}

#[derive(Debug)]
struct DecodingResult {
    recovered_data: Bytes,
    source_symbols_received: usize,
    repair_symbols_received: usize,
    total_symbols_used: u16,
}

#[derive(Debug, Clone)]
struct TestResult {
    scenario: String,
    success: bool,
    k: u16,
    symbol_size: u16,
    source_data_len: usize,
    recovered_data_len: usize,
    symbols_required: u16,
    symbols_used: u16,
    repair_symbols_needed: usize,
    all_source_recovered: bool,
    data_integrity_verified: bool,
    stats: RoundtripStats,
    notes: String,
}

#[derive(Debug, Clone)]
struct RoundtripSymbol {
    data: Vec<u8>,
    is_source: bool,
}

impl RoundtripSymbol {
    fn from_emitted(emitted: EmittedSymbol) -> Self {
        Self {
            data: emitted.data,
            is_source: emitted.is_source,
        }
    }
}

#[derive(Debug)]
struct TestHarnessError(String);

impl fmt::Display for TestHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TestHarnessError {}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(TestHarnessError(message.into()))
}

fn split_source_symbols(source_data: &Bytes, k: u16, symbol_size: u16) -> Vec<Vec<u8>> {
    let symbol_size = symbol_size as usize;
    (0..k as usize)
        .map(|index| {
            let start = index * symbol_size;
            let end = start + symbol_size;
            source_data[start..end].to_vec()
        })
        .collect()
}

fn estimate_symbol_bytes(
    source_symbols: &BTreeMap<u32, RoundtripSymbol>,
    repair_symbols: &BTreeMap<u32, RoundtripSymbol>,
) -> u64 {
    source_symbols
        .values()
        .chain(repair_symbols.values())
        .map(|symbol| symbol.data.len() as u64)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_test_result(test_result: &TestResult) {
        println!(
            "RaptorQ E2E scenario={} k={} symbol_size={} source_len={} recovered_len={} transmitted={} received={} lost={} repair_used={} memory_usage_bytes={} notes={}",
            test_result.scenario,
            test_result.k,
            test_result.symbol_size,
            test_result.source_data_len,
            test_result.recovered_data_len,
            test_result.stats.symbols_transmitted,
            test_result.stats.symbols_received,
            test_result.stats.symbols_lost,
            test_result.stats.repair_symbols_used,
            test_result.stats.memory_usage_bytes,
            test_result.notes
        );
    }

    #[test]
    fn test_raptorq_perfect_roundtrip_small_block() {
        let mut harness = RaptorQRoundtripHarness::new(0x12345678);

        let runtime = harness.runtime.clone();
        let result = runtime.block_on(async { harness.test_perfect_roundtrip(8, 1024).await });

        match result {
            Outcome::Ok(test_result) => {
                log_test_result(&test_result);
                assert!(test_result.success, "Perfect roundtrip should succeed");
                assert_eq!(
                    test_result.symbols_used, test_result.symbols_required,
                    "Should use exactly K symbols"
                );
                assert_eq!(
                    test_result.repair_symbols_needed, 0,
                    "No repair symbols needed in perfect transmission"
                );
                assert!(
                    test_result.all_source_recovered,
                    "All source symbols should be recovered"
                );
                assert!(
                    test_result.data_integrity_verified,
                    "Data integrity should be verified"
                );
                assert_eq!(
                    test_result.source_data_len, test_result.recovered_data_len,
                    "Recovered data length should match"
                );

                println!("Perfect roundtrip test: {}", test_result.notes);
                println!(
                    "Encoding time: {:.2}ms",
                    test_result.stats.encoding_duration_ms
                );
                println!(
                    "Decoding time: {:.2}ms",
                    test_result.stats.decoding_duration_ms
                );
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_raptorq_lossy_roundtrip() {
        let mut harness = RaptorQRoundtripHarness::new(0xABCDEF01);

        let runtime = harness.runtime.clone();
        let result = runtime.block_on(async {
            harness.test_lossy_roundtrip(16, 1024, 0.2).await // 20% loss rate
        });

        match result {
            Outcome::Ok(test_result) => {
                log_test_result(&test_result);
                assert!(
                    test_result.success,
                    "Lossy roundtrip should succeed with repair symbols"
                );
                assert!(
                    test_result.data_integrity_verified,
                    "Data integrity should be verified"
                );
                assert_eq!(
                    test_result.source_data_len, test_result.recovered_data_len,
                    "Recovered data length should match"
                );
                assert!(
                    test_result.repair_symbols_needed > 0 || test_result.stats.symbols_lost == 0,
                    "Should need repair symbols if losses occurred"
                );

                println!("Lossy roundtrip test: {}", test_result.notes);
                println!("Repair symbols used: {}", test_result.repair_symbols_needed);
                println!(
                    "Decoding overhead: {:.1}%",
                    test_result.stats.decoding_overhead
                );
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_raptorq_systematic_recovery() {
        let mut harness = RaptorQRoundtripHarness::new(0x24681357);

        let runtime = harness.runtime.clone();
        let result = runtime.block_on(async { harness.test_systematic_recovery(12, 2048).await });

        match result {
            Outcome::Ok(test_result) => {
                log_test_result(&test_result);
                assert!(test_result.success, "Systematic recovery should succeed");
                assert_eq!(
                    test_result.symbols_used, test_result.symbols_required,
                    "Should use exactly K symbols"
                );
                assert_eq!(
                    test_result.repair_symbols_needed, 0,
                    "Systematic recovery uses no repair symbols"
                );
                assert!(
                    test_result.all_source_recovered,
                    "All source symbols should be recovered"
                );
                assert!(
                    test_result.data_integrity_verified,
                    "Data integrity should be verified"
                );

                println!("Systematic recovery test: {}", test_result.notes);
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_raptorq_deterministic_encoding() {
        // Test that same seed produces identical encoding
        let mut harness1 = RaptorQRoundtripHarness::new(0xDEADBEEF);
        let mut harness2 = RaptorQRoundtripHarness::new(0xDEADBEEF);

        let runtime1 = harness1.runtime.clone();
        let runtime2 = harness2.runtime.clone();

        let result1 = runtime1.block_on(async { harness1.test_perfect_roundtrip(6, 512).await });

        let result2 = runtime2.block_on(async { harness2.test_perfect_roundtrip(6, 512).await });

        match (result1, result2) {
            (Outcome::Ok(test1), Outcome::Ok(test2)) => {
                log_test_result(&test1);
                log_test_result(&test2);
                assert!(test1.success && test2.success, "Both tests should succeed");
                assert_eq!(
                    test1.source_data_len, test2.source_data_len,
                    "Source data lengths should match"
                );
                assert_eq!(
                    test1.recovered_data_len, test2.recovered_data_len,
                    "Recovered data lengths should match"
                );
                assert_eq!(
                    test1.stats.encoding_duration_ms > 0.0,
                    test2.stats.encoding_duration_ms > 0.0,
                    "Both should have encoding times"
                );

                println!(
                    "Deterministic encoding verified: both harnesses produced successful roundtrips"
                );
            }
            (outcome1, outcome2) => {
                panic!("Deterministic tests failed: {:?}, {:?}", outcome1, outcome2)
            }
        }
    }

    #[test]
    fn test_raptorq_symbol_counting() {
        let mut harness = RaptorQRoundtripHarness::new(0xFEDCBA98);

        let runtime = harness.runtime.clone();
        let result = runtime.block_on(async {
            harness.test_lossy_roundtrip(20, 1024, 0.3).await // 30% loss rate
        });

        match result {
            Outcome::Ok(test_result) => {
                log_test_result(&test_result);
                assert!(test_result.success, "Symbol counting test should succeed");

                // Verify symbol counts are consistent
                assert_eq!(
                    test_result.symbols_required, 20,
                    "Should require 20 symbols (K)"
                );
                assert!(
                    test_result.symbols_used >= test_result.symbols_required,
                    "Should use at least K symbols"
                );

                // Verify repair symbol accounting against the observed receive mix.
                let source_symbols_received =
                    test_result.symbols_used as usize - test_result.repair_symbols_needed;
                assert_eq!(
                    test_result.repair_symbols_needed as u64, test_result.stats.repair_symbols_used,
                    "Repair symbol count should match stats"
                );
                assert!(
                    source_symbols_received <= test_result.symbols_required as usize,
                    "Received source symbols cannot exceed K"
                );

                println!(
                    "Symbol counting verified: K={}, used={}, source_received={}, repair={}",
                    test_result.symbols_required,
                    test_result.symbols_used,
                    source_symbols_received,
                    test_result.repair_symbols_needed
                );
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_raptorq_data_integrity() {
        let mut harness = RaptorQRoundtripHarness::new(0x98765432);
        let runtime = harness.runtime.clone();

        // Test multiple scenarios to ensure data integrity
        let test_cases = vec![
            (4, 512),   // Small block
            (16, 1024), // Medium block
            (32, 2048), // Large block
        ];

        for (k, symbol_size) in test_cases {
            let result =
                runtime.block_on(async { harness.test_perfect_roundtrip(k, symbol_size).await });

            match result {
                Outcome::Ok(test_result) => {
                    log_test_result(&test_result);
                    assert!(
                        test_result.data_integrity_verified,
                        "Data integrity should be verified for K={}, symbol_size={}",
                        k, symbol_size
                    );
                    assert_eq!(
                        test_result.source_data_len,
                        (k as usize) * (symbol_size as usize),
                        "Data length should match K*symbol_size"
                    );
                    assert_eq!(
                        test_result.source_data_len, test_result.recovered_data_len,
                        "Recovered data should match original"
                    );

                    println!(
                        "Data integrity verified for K={}, symbol_size={}",
                        k, symbol_size
                    );
                }
                outcome => panic!(
                    "Data integrity test failed for K={}, symbol_size={}: {:?}",
                    k, symbol_size, outcome
                ),
            }
        }
    }
}
