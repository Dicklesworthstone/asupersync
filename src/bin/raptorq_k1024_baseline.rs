//! Quick K=1024 baseline to establish profiling methodology while K=10000 builds.

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use std::time::Instant;

fn main() {
    println!("Quick K=1024 baseline for profiling methodology");

    let k = 1024;
    let symbol_size = 1316;
    let loss_fraction = 0.70; // High loss to trigger matrix operations
    let extra_repair = 200;

    let total_bytes = k * symbol_size;
    println!(
        "K={}, loss={}%, total={:.1}MB",
        k,
        loss_fraction * 100.0,
        total_bytes as f64 / 1024.0 / 1024.0
    );

    // Generate test data
    let mut source_data = vec![0u8; total_bytes];
    let mut rng_state = 0x12345678u64;
    for byte in source_data.iter_mut() {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (rng_state >> 16) as u8;
    }

    println!("Creating encoder...");
    let encoder_start = Instant::now();
    let object_id = ObjectId::new([0; 32]);
    let encoder = SystematicEncoder::new(object_id, &source_data, symbol_size)
        .expect("encoder creation failed");
    println!(
        "Encoder: {:.1}ms",
        encoder_start.elapsed().as_secs_f64() * 1000.0
    );

    println!("Generating repair symbols...");
    let repair_start = Instant::now();
    let mut repair_symbols = Vec::new();
    for i in 0..extra_repair {
        if let Some(symbol) = encoder.repair_symbol(i) {
            repair_symbols.push((k + i, symbol));
        }
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
    for (i, &is_lost) in loss_pattern.iter().enumerate() {
        if !is_lost {
            if let Some(symbol) = encoder.source_symbol(i) {
                received_symbols.push(ReceivedSymbol {
                    id: i,
                    data: symbol,
                });
            }
        }
    }

    let needed_repairs = loss_count + 50;
    for (repair_id, repair_data) in repair_symbols.into_iter().take(needed_repairs) {
        received_symbols.push(ReceivedSymbol {
            id: repair_id,
            data: repair_data,
        });
    }
    println!("Received symbols: {}", received_symbols.len());

    println!("Creating decoder...");
    let encoding_params = encoder.encoding_params();
    let mut decoder = InactivationDecoder::new(encoding_params);

    for symbol in received_symbols {
        decoder.add_symbol(symbol).expect("symbol addition failed");
    }

    println!("=== DECODE (PROFILING TARGET) ===");
    let decode_start = Instant::now();
    let decode_result = decoder.decode().expect("decode failed");
    let decode_time = decode_start.elapsed();

    println!("Decode time: {:.1}ms", decode_time.as_secs_f64() * 1000.0);
    println!(
        "Throughput: {:.1} MB/s",
        (total_bytes as f64 / 1024.0 / 1024.0) / decode_time.as_secs_f64()
    );

    // Quick verification - reconstruct source from symbols
    let mut decoded_flat = Vec::new();
    for symbol in &decode_result.source {
        decoded_flat.extend_from_slice(symbol);
    }
    assert_eq!(decoded_flat.len(), source_data.len());

    // Show decode stats
    println!(
        "Decode stats: peeling={}, inactivated={}, matrix_ops={}",
        decode_result.stats.peeled,
        decode_result.stats.inactivated,
        decode_result.stats.dense_matrix_operations.unwrap_or(0)
    );

    println!("✓ Decode successful");
}
