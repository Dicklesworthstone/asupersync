//! Quick verification that blocked Gaussian elimination produces correct results.

#[cfg(feature = "test-internals")]
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
#[cfg(feature = "test-internals")]
use asupersync::raptorq::systematic::SystematicEncoder;

#[cfg(feature = "test-internals")]
fn main() {
    println!("Verifying blocked Gaussian elimination correctness...");

    // Test scenario: K=1000 with 70% loss (forces dense matrix solving)
    let k = 1000;
    let symbol_size = 1316;
    let loss_rate = 0.70;
    let seed = 0x12345678u64;

    println!("Test parameters: K={}, symbol_size={}, loss_rate={}%",
        k, symbol_size, loss_rate * 100.0);

    // Generate source data
    let mut source_symbols = Vec::with_capacity(k);
    let mut rng_state = 0x87654321u64;
    for _i in 0..k {
        let mut symbol_data = vec![0u8; symbol_size];
        for byte in symbol_data.iter_mut() {
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (rng_state >> 16) as u8;
        }
        source_symbols.push(symbol_data);
    }

    println!("Creating encoder...");
    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation failed");

    // Create loss pattern
    let loss_count = (k as f64 * loss_rate) as usize;
    let mut loss_pattern = vec![false; k];
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

    println!("Loss pattern: {}/{} symbols lost", losses_applied, k);

    // Create decoder with received symbols
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let mut received_symbols = decoder.constraint_symbols();

    for (i, &is_lost) in loss_pattern.iter().enumerate() {
        if !is_lost {
            let esi = i as u32;
            received_symbols.push(ReceivedSymbol::source(esi, source_symbols[i].clone()));
        }
    }

    // Add repair symbols
    let needed_repairs = loss_count + 50;
    for i in 0..needed_repairs {
        let repair_esi = (k + i) as u32;
        let (cols, coefs) = decoder.repair_equation(repair_esi).expect("repair equation failed");
        let repair_data = encoder.repair_symbol(repair_esi);
        received_symbols.push(ReceivedSymbol::repair(repair_esi, cols, coefs, repair_data));
    }

    println!("Received symbols: {}", received_symbols.len());

    // Decode using blocked elimination
    println!("Decoding with blocked Gaussian elimination...");
    let decode_start = std::time::Instant::now();
    let decode_result = decoder.decode(&received_symbols).expect("decode failed");
    let decode_time = decode_start.elapsed();

    println!("Decode completed in {:.1}ms", decode_time.as_millis());
    println!("Decode stats: peeled={}, inactivated={}, gauss_ops={}",
        decode_result.stats.peeled,
        decode_result.stats.inactivated,
        decode_result.stats.gauss_ops);

    // Verify correctness
    let mut decoded_flat = Vec::new();
    for symbol in &decode_result.source {
        decoded_flat.extend_from_slice(symbol);
    }

    let mut source_flat = Vec::new();
    for symbol in &source_symbols {
        source_flat.extend_from_slice(symbol);
    }

    println!("Verifying decoded data...");
    assert_eq!(decoded_flat.len(), source_flat.len(), "Length mismatch");

    let mut mismatches = 0;
    for (i, (&expected, &actual)) in source_flat.iter().zip(decoded_flat.iter()).enumerate() {
        if expected != actual {
            mismatches += 1;
            if mismatches <= 5 {
                println!("Mismatch at byte {}: expected {}, got {}", i, expected, actual);
            }
        }
    }

    if mismatches == 0 {
        println!("✓ SUCCESS: Blocked elimination produces correct results!");
        println!("✓ Decoded {:.1}MB correctly",
            (source_flat.len() as f64) / (1024.0 * 1024.0));
        println!("✓ Throughput: {:.1} MB/s",
            (source_flat.len() as f64 / (1024.0 * 1024.0)) / decode_time.as_secs_f64());
    } else {
        panic!("❌ FAILURE: {} byte mismatches detected!", mismatches);
    }
}

#[cfg(not(feature = "test-internals"))]
fn main() {
    println!("This verification requires the test-internals feature.");
    println!("Run with: cargo run --bin verify_blocked_elimination --features test-internals");
}