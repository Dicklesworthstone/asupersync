//! RaptorQ profiling test for large K workloads.
//!
//! Simple standalone binary to profile encoder/decoder hot paths.
//! Run with: perf record --call-graph dwarf ./target/release-perf/raptorq_profile_test

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice, gf256_mul_slice};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;

fn main() {
    println!("Starting RaptorQ large K profiling test...");

    // Test parameters for realistic K=1024 scenario
    let k = 1024;
    let symbol_size = 1316; // ~1.3MB total payload
    let loss_fraction = 0.6; // 60% loss
    let extra_repair = 200;

    let total_bytes = k * symbol_size;
    println!(
        "Testing K={}, symbol_size={}, total_bytes={}",
        k, symbol_size, total_bytes
    );

    // Generate test data
    let mut source_data = vec![0u8; total_bytes];
    let mut rng_state = 0x12345678u64;
    for byte in source_data.iter_mut() {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (rng_state >> 16) as u8;
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
    let object_id = ObjectId::new([0; 32]);
    let encoder = SystematicEncoder::new(object_id, &source_data, symbol_size)
        .expect("encoder creation failed");

    println!("Generating repair symbols...");
    let mut repair_symbols = Vec::with_capacity(extra_repair);
    for i in 0..extra_repair {
        if let Some(symbol) = encoder.repair_symbol(i) {
            repair_symbols.push((k + i, symbol));
        }
    }

    // **HOT PATH TEST 3: Decoder with realistic loss pattern**
    println!("Creating loss pattern and received symbols...");

    // Create scattered loss pattern
    let mut loss_pattern = vec![false; k]; // false = available
    let loss_count = (k as f64 * loss_fraction) as usize;
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

    // Collect received symbols
    let mut received_symbols = Vec::new();

    // Add available source symbols
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

    // Add repair symbols to ensure decodability
    let needed_repairs = loss_count + 50; // Some overhead
    for (repair_id, repair_data) in repair_symbols.into_iter().take(needed_repairs) {
        received_symbols.push(ReceivedSymbol {
            id: repair_id,
            data: repair_data,
        });
    }

    println!("Received symbols: {}", received_symbols.len());

    // **HOT PATH TEST 4: Inactivation decoding (matrix operations)**
    println!("Creating decoder and adding symbols...");
    let encoding_params = encoder.encoding_params();
    let mut decoder = InactivationDecoder::new(encoding_params);

    // Add symbols - this may involve matrix operations
    let symbols_added = received_symbols.len();
    for symbol in received_symbols {
        decoder.add_symbol(symbol).expect("symbol addition failed");
    }

    println!("Added {} symbols to decoder", symbols_added);

    // **HOT PATH TEST 5: Decode (Gaussian elimination and gap handling)**
    println!("Starting decode - this is where matrix solve happens...");
    let start = std::time::Instant::now();

    let decoded = decoder.decode().expect("decode failed");

    let decode_time = start.elapsed();
    println!(
        "Decode completed in {:.2}ms",
        decode_time.as_secs_f64() * 1000.0
    );

    // Verify correctness
    if decoded.len() != source_data.len() {
        panic!(
            "Decoded length mismatch: {} vs {}",
            decoded.len(),
            source_data.len()
        );
    }

    if decoded != source_data {
        panic!("Decoded data mismatch!");
    }

    println!("Success! Decoded data matches original.");
    println!("Profile complete. Check perf report for hotspots.");
}
