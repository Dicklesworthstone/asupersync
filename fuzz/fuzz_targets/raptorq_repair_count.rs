#![no_main]

use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

const K: usize = 10;
const SYMBOL_SIZE: usize = 8;
const SEED: u64 = 0x5EED_5EED_5EED_5EED;
const REPAIR_COUNTS: [usize; 4] = [1, 10, 100, 1000];

fuzz_target!(|data: &[u8]| {
    let source = source_block(data);

    for repair_count in REPAIR_COUNTS {
        let mut encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED)
            .expect("fixed K source block must be encodable");
        let repairs = encoder.emit_repair(repair_count);

        assert_eq!(
            repairs.len(),
            repair_count,
            "emit_repair must return exactly the requested repair count"
        );
        assert_eq!(
            encoder.stats().repair_symbols_generated,
            repair_count,
            "encoder stats must count exactly the requested repair symbols"
        );
    }
});

fn source_block(data: &[u8]) -> Vec<Vec<u8>> {
    (0..K)
        .map(|row| {
            (0..SYMBOL_SIZE)
                .map(|col| {
                    let fallback = (row as u8).wrapping_mul(31) ^ (col as u8).wrapping_mul(17);
                    data.get((row * SYMBOL_SIZE + col) % data.len().max(1))
                        .copied()
                        .unwrap_or(fallback)
                        ^ fallback
                })
                .collect()
        })
        .collect()
}
