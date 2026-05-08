//! RaptorQ profiling test for large K workloads.
//!
//! Simple standalone binary to profile encoder/decoder hot paths.
//!
//! Usage:
//! CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/rch_target_raptorq_profile_test}
//! rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo build --profile release-perf --bin raptorq_profile_test --features simd-intrinsics
//! perf record --call-graph dwarf $CARGO_TARGET_DIR/release-perf/raptorq_profile_test

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice, gf256_mul_slice};
use asupersync::raptorq::systematic::SystematicEncoder;

fn main() {
    println!("Starting RaptorQ large K profiling test...");

    // Test parameters for realistic K=1024 scenario
    let k = 1024;
    let symbol_size = 1316; // ~1.3MB total payload
    let loss_fraction = 0.6; // 60% loss
    let loss_count = (k as f64 * loss_fraction) as usize;
    let repair_margin = 50;
    let extra_repair = loss_count + repair_margin;
    let seed = 42u64;

    println!(
        "Testing K={}, symbol_size={}, loss_fraction={:.1}%",
        k,
        symbol_size,
        loss_fraction * 100.0
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

    // **HOT PATH TEST 1: GF256 bulk operations**
    println!("Testing GF256 bulk operations...");
    for iteration in 0..100 {
        let mut test_data = vec![42u8; 65536]; // 64KB test
        let scalar = Gf256::new((iteration % 255 + 1) as u8);

        // Test gf256_mul_slice - should show up as hotspot
        gf256_mul_slice(&mut test_data, scalar);

        // Test gf256_addmul_slice - typically most expensive
        let src_data = vec![(iteration % 256) as u8; 65536];
        gf256_addmul_slice(&mut test_data, &src_data, scalar);
    }

    // **HOT PATH TEST 2: Encoder creation and symbol generation**
    println!("Creating encoder...");
    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation failed");

    println!("Generating repair symbols...");
    let mut repair_symbols = Vec::with_capacity(extra_repair);
    for i in 0..extra_repair {
        let esi = k as u32 + i as u32;
        let symbol = encoder.repair_symbol(esi);
        repair_symbols.push((esi, symbol));
    }

    // **HOT PATH TEST 3: Decoder with realistic loss pattern**
    println!("Creating loss pattern and received symbols...");

    // Create scattered loss pattern
    let mut loss_pattern = vec![false; k]; // false = available
    rng_state = 0xDEADBEEF;
    let mut losses_applied = 0;

    while losses_applied < loss_count {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (rng_state % k as u64) as usize;
        if !loss_pattern[idx] {
            loss_pattern[idx] = true; // true = lost
            losses_applied += 1;
        }
    }

    println!("Loss pattern: {}/{} symbols lost", losses_applied, k);

    println!("Creating decoder...");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    // Collect received symbols for decoding
    let mut received_symbols = decoder.constraint_symbols();

    // Add available source symbols
    for (i, &is_lost) in loss_pattern.iter().enumerate() {
        if !is_lost {
            received_symbols.push(ReceivedSymbol::source(i as u32, source_symbols[i].clone()));
        }
    }

    // Add repair symbols to ensure decodability
    for (repair_esi, repair_data) in repair_symbols {
        let (cols, coefs) = decoder
            .repair_equation(repair_esi)
            .expect("repair equation failed");
        received_symbols.push(ReceivedSymbol::repair(repair_esi, cols, coefs, repair_data));
    }

    println!("Received symbols: {}", received_symbols.len());

    // **HOT PATH TEST 4: Decode (Gaussian elimination and gap handling)**
    println!("Starting decode - this is where matrix solve happens...");
    let start = std::time::Instant::now();

    let decode_result = decoder.decode(&received_symbols).expect("decode failed");

    let decode_time = start.elapsed();
    println!(
        "Decode completed in {:.2}ms",
        decode_time.as_secs_f64() * 1000.0
    );

    // Verify correctness
    let decoded_symbols = decode_result.source;
    if decoded_symbols.len() != k {
        panic!(
            "Decoded symbol count mismatch: {} vs {}",
            decoded_symbols.len(),
            k
        );
    }

    for (i, (original, decoded)) in source_symbols
        .iter()
        .zip(decoded_symbols.iter())
        .enumerate()
    {
        if original != decoded {
            panic!("Symbol {} data mismatch!", i);
        }
    }

    println!("Success! Decoded data matches original.");
    println!("Profile complete. Check perf report for hotspots.");
}
