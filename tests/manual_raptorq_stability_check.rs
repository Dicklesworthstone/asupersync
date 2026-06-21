//! Manual RaptorQ encoder stability validation
//! This test demonstrates the stability testing approach for RaptorQ encoder output

use asupersync::raptorq::systematic::SystematicEncoder;
use std::collections::HashMap;

/// Generate deterministic source symbols for testing.
fn generate_deterministic_source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..symbol_size)
                .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                .collect()
        })
        .collect()
}

/// Test encoder output stability for given parameters
fn test_encoder_stability(k: usize, symbol_size: usize, seed: u64, repair_count: usize) -> String {
    let source_symbols = generate_deterministic_source_symbols(k, symbol_size);

    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation should succeed");

    let params = encoder.params();

    // Collect repair symbols
    let mut repair_data = Vec::new();
    for i in 0..repair_count {
        let esi = (k + i) as u32;
        let symbol = encoder.repair_symbol(esi);
        repair_data.push((esi, hex::encode(&symbol)));
    }

    // Create deterministic output summary
    format!(
        "K={}, symbol_size={}, seed={:08X}\n\
         RFC6330_params: K'={}, L={}, S={}, H={}, W={}\n\
         repair_symbols:\n{}",
        k,
        symbol_size,
        seed,
        params.k_prime,
        params.l,
        params.s,
        params.h,
        params.w,
        repair_data
            .iter()
            .map(|(esi, hex)| format!("  ESI_{}: {}", esi, &hex[..16.min(hex.len())]))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[test]
fn test_encoder_determinism_validation() {
    // Test cases: K=10/100/1000 with fixed seeds
    let test_cases = [
        (10, 64, 0x12345678, 3),
        (100, 128, 0xDEADBEEF, 5),
        (1000, 256, 0xCAFEBABE, 8),
    ];

    println!("=== RaptorQ Encoder Stability Test Results ===");

    for (k, symbol_size, seed, repair_count) in test_cases {
        println!(
            "\n--- Test Case: K={}, symbol_size={}, seed={:08X} ---",
            k, symbol_size, seed
        );

        // Run same test multiple times to verify determinism
        let result1 = test_encoder_stability(k, symbol_size, seed, repair_count);
        let result2 = test_encoder_stability(k, symbol_size, seed, repair_count);
        let result3 = test_encoder_stability(k, symbol_size, seed, repair_count);

        // Verify determinism
        assert_eq!(result1, result2, "Non-deterministic output detected!");
        assert_eq!(result1, result3, "Non-deterministic output detected!");

        println!("{}", result1);

        // Test seed sensitivity
        let different_seed_result = test_encoder_stability(k, symbol_size, seed + 1, repair_count);
        assert_ne!(
            result1, different_seed_result,
            "Encoder not sensitive to seed changes!"
        );

        println!("✓ Determinism and seed sensitivity validated");
    }

    println!("\n=== STABILITY VALIDATION COMPLETE ===");
    println!("✓ All encoder outputs are deterministic");
    println!("✓ Different seeds produce different outputs");
    println!("✓ RFC 6330 parameter derivation is stable");
}

#[test]
fn test_parameter_stability() {
    // Verify RFC 6330 parameter derivation consistency
    let k_values = [10, 25, 50, 100, 256, 500, 1000];
    let mut params_table = HashMap::new();

    for &k in &k_values {
        let source_symbols = generate_deterministic_source_symbols(k, 64);
        let encoder = SystematicEncoder::new(&source_symbols, 64, 0)
            .expect("encoder creation should succeed");

        let params = encoder.params();
        params_table.insert(k, (params.k_prime, params.l, params.s, params.h, params.w));
    }

    println!("=== RFC 6330 Parameter Stability ===");
    println!("K      -> K'    L     S   H    W");
    for &k in &k_values {
        let (k_prime, l, s, h, w) = params_table[&k];
        println!("{:4}   -> {:4} {:4} {:3} {:3} {:4}", k, k_prime, l, s, h, w);
    }

    // Verify specific RFC 6330 Table 2 values (regression detection).
    assert_eq!(params_table[&10], (10, 27, 7, 10, 17));
    assert_eq!(params_table[&25], (26, 47, 11, 10, 37));
    assert_eq!(params_table[&50], (55, 78, 13, 10, 67));
    assert_eq!(params_table[&100], (101, 128, 17, 10, 113));
    assert_eq!(params_table[&256], (257, 296, 29, 10, 271));
    assert_eq!(params_table[&500], (511, 558, 37, 10, 523));
    assert_eq!(params_table[&1000], (1002, 1071, 59, 10, 1021));

    println!("✓ Parameter derivation matches expected RFC 6330 Table 2 values");
}
