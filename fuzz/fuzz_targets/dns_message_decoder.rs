//! DNS message parser fuzz target.
//!
//! This target is intentionally distinct from `dns_lookup_decoder`: it drives
//! the production DNS response parser and name decoder directly, without a
//! fake resolver transport. Keeping it standalone also prevents nested
//! `#![no_main]` attributes when all registered fuzz binaries are compiled.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::net::dns::{decode_dns_name_for_fuzz, parse_dns_response_for_fuzz};
use libfuzzer_sys::fuzz_target;

const MAX_PACKET_LEN: usize = 4096;

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    mode: DecodeMode,
    expected_id: u16,
    start_offset: u16,
    packet: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum DecodeMode {
    Response,
    Name,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    if input.packet.len() > MAX_PACKET_LEN {
        return;
    }

    match input.mode {
        DecodeMode::Response => {
            let _ = parse_dns_response_for_fuzz(&input.packet, input.expected_id);
        }
        DecodeMode::Name => {
            if input.packet.is_empty() {
                return;
            }

            let mut offset = usize::from(input.start_offset) % input.packet.len();
            let result = decode_dns_name_for_fuzz(&input.packet, &mut offset);
            if result.is_ok() {
                assert!(
                    offset <= input.packet.len(),
                    "successful DNS name decode must leave the cursor in bounds"
                );
            }
        }
    }
});
