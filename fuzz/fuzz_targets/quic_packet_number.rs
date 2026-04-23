#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::net::quic_core::decode_packet_number_reconstruct;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct PacketNumberFuzzData {
    truncated_pn: u32,
    pn_len: u8,
    largest_pn: u64,
}

fuzz_target!(|data: PacketNumberFuzzData| {
    // The oracle: decode_packet_number_reconstruct must not panic for any input.
    // It should either return Ok(full_pn) or Err(QuicCoreError).
    // Note: the implementation enforces pn_len in 1..=4.
    
    let res = std::panic::catch_unwind(|| {
        decode_packet_number_reconstruct(data.truncated_pn, data.pn_len, data.largest_pn)
    });
    
    match res {
        Ok(Ok(full_pn)) => {
            // If it succeeds, the difference between full_pn and largest_pn
            // should not exceed half the representable space of the pn_len, 
            // unless we hit boundaries (RFC 9000). But simply surviving without panic is the primary fuzz goal.
            
            // Re-encoding should theoretically give us back the truncated_pn if we truncate it to pn_len bytes.
            let mask = match data.pn_len {
                1 => 0xFF,
                2 => 0xFFFF,
                3 => 0xFF_FFFF,
                4 => 0xFFFF_FFFF,
                _ => unreachable!("decode_packet_number_reconstruct returned Ok for pn_len not in 1..=4"),
            };
            
            let truncated_reencoded = (full_pn & (mask as u64)) as u32;
            let truncated_input_masked = data.truncated_pn & mask;
            
            assert_eq!(
                truncated_reencoded, truncated_input_masked,
                "Truncated re-encoding mismatch: original={}, reencoded={}, pn_len={}, largest_pn={}",
                truncated_input_masked, truncated_reencoded, data.pn_len, data.largest_pn
            );
        }
        Ok(Err(_err)) => {
            // Valid rejection (e.g. invalid pn_len)
            assert!(!(1..=4).contains(&data.pn_len), "Valid pn_len 1..=4 should never return Err");
        }
        Err(e) => {
            std::panic::resume_unwind(e);
        }
    }
});