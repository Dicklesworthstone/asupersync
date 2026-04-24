#![allow(warnings)]
//! Golden snapshot test for RaptorQ EncoderStats display output.

use asupersync::raptorq::systematic::SystematicEncoder;

#[test]
fn test_encoder_stats_display_golden() {
    let source_symbols = vec![vec![42u8; 128]; 8]; // 8 symbols of 128 bytes
    let symbol_size = 128;
    let seed = 12345;

    let mut encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed).unwrap();

    insta::assert_snapshot!(
        "encoder_stats_initial_scrubbed",
        encoder.stats().to_string()
    );

    let _ = encoder.emit_systematic();
    insta::assert_snapshot!(
        "encoder_stats_after_systematic_scrubbed",
        encoder.stats().to_string()
    );

    let _ = encoder.emit_repair(4);
    insta::assert_snapshot!(
        "encoder_stats_after_repair_scrubbed",
        encoder.stats().to_string()
    );
}
