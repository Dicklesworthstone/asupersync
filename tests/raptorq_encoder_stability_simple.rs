//! Simplified RaptorQ encoder stability test to debug compilation issues.

use asupersync::raptorq::systematic::SystematicEncoder;
use insta::assert_debug_snapshot;

#[test]
fn test_encoder_simple_k10() {
    // Generate deterministic source symbols
    let k = 10;
    let symbol_size = 64;
    let seed = 0x12345678;

    let source_symbols: Vec<Vec<u8>> = (0..k)
        .map(|i| {
            (0..symbol_size)
                .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                .collect()
        })
        .collect();

    // Create encoder with fixed seed
    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation should succeed");

    // Generate repair symbol
    let repair_esi = k as u32;
    let repair_symbol = encoder.repair_symbol(repair_esi);

    // Simple golden capture
    let output = format!("K={}, symbol_size={}, seed={:08x}, repair_len={}, repair_hex={}",
        k, symbol_size, seed, repair_symbol.len(), hex::encode(&repair_symbol));

    assert_debug_snapshot!("simple_encoder_k10", output);
}