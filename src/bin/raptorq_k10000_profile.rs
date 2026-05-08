//! RaptorQ K=10000 decoder profiling harness.
//!
//! Targets the next performance bottleneck after gf256_addmul_slice SIMD optimization.
//! Expected hotspots: matrix solve (Gaussian elimination), gap-handling, dense core.
//!
//! Usage:
//! cargo build --profile release-perf --bin raptorq_k10000_profile --features simd-intrinsics
//! samply record --save-only -o k10000_cpu.json -- ./target/release-perf/raptorq_k10000_profile

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use std::time::Instant;

fn main() {
    println!("RaptorQ K=10000 decoder profiling - post-gf256-SIMD bottleneck analysis");

    // K=10000 scenario parameters
    let k = 10000;
    let symbol_size = 1316; // ~13MB total payload
    let loss_fraction = 0.70; // 70% loss to force heavy matrix operations
    let extra_repair = 1000; // Sufficient repair symbols
    let seed = 0x87654321u64;

    let total_bytes = k * symbol_size;
    println!("Scenario: K={}, symbol_size={}, total_bytes={:.1}MB, loss={}%",
        k, symbol_size, total_bytes as f64 / 1024.0 / 1024.0, loss_fraction * 100.0);

    // Generate source symbols as Vec<Vec<u8>> - proper API format
    println!("Generating source symbols...");
    let mut source_symbols = Vec::with_capacity(k);
    let mut rng_state = 0x87654321u64;
    for _symbol_idx in 0..k {
        let mut symbol_data = vec![0u8; symbol_size];
        for byte in symbol_data.iter_mut() {
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (rng_state >> 16) as u8;
        }
        source_symbols.push(symbol_data);
    }

    println!("=== PROFILING TARGET 1: ENCODER (baseline) ===");
    let encoder_start = Instant::now();

    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation failed");

    println!("Encoder created in {:.2}ms", encoder_start.elapsed().as_secs_f64() * 1000.0);

    println!("=== PROFILING TARGET 2: REPAIR SYMBOL GENERATION ===");
    let repair_start = Instant::now();

    let mut repair_symbols = Vec::with_capacity(extra_repair);
    for i in 0..extra_repair {
        let esi = (k + i) as u32;
        let symbol_data = encoder.repair_symbol(esi);
        repair_symbols.push((esi, symbol_data));
    }

    println!("Generated {} repair symbols in {:.2}ms",
        repair_symbols.len(), repair_start.elapsed().as_secs_f64() * 1000.0);

    println!("=== PROFILING TARGET 3: LOSS PATTERN SIMULATION ===");
    let loss_start = Instant::now();

    // Create realistic scattered loss pattern for K=10000
    let mut loss_pattern = vec![false; k]; // false = available
    let loss_count = (k as f64 * loss_fraction) as usize;
    rng_state = 0xDEADBEEF12345678u64;
    let mut losses_applied = 0;

    while losses_applied < loss_count {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (rng_state % k as u64) as usize;
        if !loss_pattern[idx] {
            loss_pattern[idx] = true; // true = lost
            losses_applied += 1;
        }
    }

    println!("Loss pattern: {}/{} symbols lost ({:.1}%) in {:.2}ms",
        losses_applied, k, (losses_applied as f64 / k as f64) * 100.0,
        loss_start.elapsed().as_secs_f64() * 1000.0);

    println!("=== PROFILING TARGET 4: DECODER CREATION ===");
    let decoder_start = Instant::now();

    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    println!("Decoder created in {:.2}ms",
        decoder_start.elapsed().as_secs_f64() * 1000.0);

    println!("=== PROFILING TARGET 5: RECEIVED SYMBOL COLLECTION ===");
    let collect_start = Instant::now();

    // Start with constraint symbols
    let mut received_symbols = decoder.constraint_symbols();

    // Add available source symbols
    for (i, &is_lost) in loss_pattern.iter().enumerate() {
        if !is_lost {
            let esi = i as u32;
            received_symbols.push(ReceivedSymbol::source(esi, source_symbols[i].clone()));
        }
    }

    // Add repair symbols to ensure decodability
    let needed_repairs = loss_count + 100; // Some safety margin
    for (repair_esi, repair_data) in repair_symbols.into_iter().take(needed_repairs) {
        let (cols, coefs) = decoder.repair_equation(repair_esi).expect("repair equation failed");
        received_symbols.push(ReceivedSymbol::repair(repair_esi, cols, coefs, repair_data));
    }

    println!("Collected {} received symbols in {:.2}ms",
        received_symbols.len(), collect_start.elapsed().as_secs_f64() * 1000.0);

    println!("=== PROFILING TARGET 6: DECODE (MAIN HOTSPOT) ===");
    println!("Expected bottlenecks: matrix solve, gap-handling, dense operations");

    let decode_start = Instant::now();

    // This is the main profiling target - decode with K=10000, 70% loss
    // Post-gf256-SIMD, expect bottlenecks in:
    // 1. Gaussian elimination matrix solve
    // 2. Gap-handling logic
    // 3. Dense core operations
    // 4. Memory allocation patterns
    let decode_result = decoder.decode(&received_symbols).expect("decode failed");

    let decode_time = decode_start.elapsed();
    println!("*** DECODE COMPLETED: {:.1}s ***", decode_time.as_secs_f64());

    // Reconstruct source data from symbols for verification
    let mut decoded_flat = Vec::new();
    for symbol in &decode_result.source {
        decoded_flat.extend_from_slice(symbol);
    }

    // Flatten original source for comparison
    let mut source_flat = Vec::new();
    for symbol in &source_symbols {
        source_flat.extend_from_slice(symbol);
    }

    // Verify correctness
    if decoded_flat.len() != source_flat.len() {
        panic!("Decoded length mismatch: {} vs {}", decoded_flat.len(), source_flat.len());
    }

    let mut corruption_count = 0;
    for (i, (&expected, &actual)) in source_flat.iter().zip(decoded_flat.iter()).enumerate() {
        if expected != actual {
            corruption_count += 1;
            if corruption_count <= 10 { // Show first 10 corruptions
                println!("Corruption at byte {}: expected {}, got {}", i, expected, actual);
            }
        }
    }

    if corruption_count > 0 {
        panic!("Decoded data has {} corrupted bytes!", corruption_count);
    }

    // Show decode stats if available
    println!("Decode stats: peeled={}, inactivated={}, gauss_ops={}",
        decode_result.stats.peeled,
        decode_result.stats.inactivated,
        decode_result.stats.gauss_ops);

    println!("✓ SUCCESS: Decoded {:.1}MB correctly in {:.1}s",
        total_bytes as f64 / 1024.0 / 1024.0, decode_time.as_secs_f64());
    println!("✓ Throughput: {:.1} MB/s",
        (total_bytes as f64 / 1024.0 / 1024.0) / decode_time.as_secs_f64());
}