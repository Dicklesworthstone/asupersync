//! Quick K=1024 baseline to establish profiling methodology while K=10000 builds.

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::SystematicEncoder;
use std::time::Instant;

fn main() {
    println!("Quick K=1024 baseline for profiling methodology");

    let k = 1024;
    let symbol_size = 1316;
    let loss_fraction = 0.70; // High loss to trigger matrix operations
    let extra_repair = 200;
    let seed = 42u64;

    let total_bytes = k * symbol_size;
    println!(
        "K={}, loss={}%, total={:.1}MB",
        k,
        loss_fraction * 100.0,
        total_bytes as f64 / 1024.0 / 1024.0
    );

    // Generate test data as k symbols of symbol_size bytes each
    let mut source_symbols = Vec::with_capacity(k);
    let mut rng_state = 0x12345678u64;
    for i in 0..k {
        let mut symbol = vec![0u8; symbol_size];
        for byte in symbol.iter_mut() {
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = ((rng_state >> 16) + i as u64) as u8;
        }
        source_symbols.push(symbol);
    }

    println!("Creating encoder...");
    let encoder_start = Instant::now();
    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation failed");
    println!(
        "Encoder: {:.1}ms",
        encoder_start.elapsed().as_secs_f64() * 1000.0
    );

    println!("Generating repair symbols...");
    let repair_start = Instant::now();
    let mut repair_symbols = Vec::new();
    for i in 0..extra_repair {
        let esi = k as u32 + i as u32;
        let symbol = encoder.repair_symbol(esi);
        repair_symbols.push((esi, symbol));
    }
    println!(
        "Repair symbols: {:.1}ms",
        repair_start.elapsed().as_secs_f64() * 1000.0
    );

    println!("Creating loss pattern...");
    let mut loss_pattern = vec![false; k];
    let loss_count = (k as f64 * loss_fraction) as usize;
    rng_state = 0xDEADBEEF;
    let mut losses_applied = 0;

    while losses_applied < loss_count {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (rng_state % k as u64) as usize;
        if !loss_pattern[idx] {
            loss_pattern[idx] = true;
            losses_applied += 1;
        }
    }
    println!("Lost {} symbols", losses_applied);

    println!("Collecting received symbols...");
    let mut received_symbols = Vec::new();

    // Add available source symbols
    for (i, &is_lost) in loss_pattern.iter().enumerate() {
        if !is_lost {
            received_symbols.push(ReceivedSymbol {
                esi: i as u32,
                is_source: true,
                columns: vec![i],
                coefficients: vec![Gf256::ONE],
                data: source_symbols[i].clone(),
            });
        }
    }

    // Add repair symbols to ensure decodability
    let needed_repairs = loss_count + 50;
    for (repair_esi, repair_data) in repair_symbols.into_iter().take(needed_repairs) {
        received_symbols.push(ReceivedSymbol {
            esi: repair_esi,
            is_source: false,
            columns: vec![], // Will be filled by decoder
            coefficients: vec![],
            data: repair_data,
        });
    }
    println!("Received symbols: {}", received_symbols.len());

    println!("Creating decoder...");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    println!("=== DECODE (PROFILING TARGET) ===");
    let decode_start = Instant::now();
    let decode_result = decoder.decode(&received_symbols).expect("decode failed");
    let decode_time = decode_start.elapsed();

    println!("Decode time: {:.1}ms", decode_time.as_secs_f64() * 1000.0);
    println!(
        "Throughput: {:.1} MB/s",
        (total_bytes as f64 / 1024.0 / 1024.0) / decode_time.as_secs_f64()
    );

    // Quick verification - check symbol count
    let decoded_symbols = decode_result.source;
    assert_eq!(decoded_symbols.len(), k);

    // Verify data matches
    for (i, (original, decoded)) in source_symbols
        .iter()
        .zip(decoded_symbols.iter())
        .enumerate()
    {
        if original != decoded {
            panic!("Symbol {} data mismatch!", i);
        }
    }

    println!("✓ Decode successful - data matches original");
}
