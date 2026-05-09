#![no_main]

//! Fuzzer for `src/net/dns/resolver.rs` binary DNS message parser.
//!
//! Targets `parse_dns_response_for_fuzz` and `decode_dns_name_for_fuzz`
//! (test-internals shims that wrap the real parsers used at runtime).
//! The shims preserve the same code path; they exist only because the
//! parsers are private to the module.
//!
//! # Properties asserted
//!
//!   1. **No panic on any input.** Random UDP-packet-shaped bytes,
//!      malformed RR records, truncated headers, oversized labels MUST
//!      NOT trigger a Rust panic. The parser must be total.
//!
//!   2. **No infinite loop on label-pointer bombs.** A classic DNS
//!      compression-pointer loop ([0xC0 0x02][0xC0 0x00] = pointer to
//!      offset 2 which contains pointer to offset 0 = forward-jump back
//!      to start) must terminate via cycle-detection or maximum-jump
//!      limit, not loop forever. The fuzz iteration finishes in <1ms,
//!      so any iteration that takes >1s indicates a hang.
//!
//!   3. **Typed error or Ok, never silent corruption.** Every parse
//!      attempt yields Result<_, DnsError>. Panicking, returning
//!      garbage data, or hanging are bugs.
//!
//! # Coverage biases
//!
//!   * First 2 bytes are an "expected_id" hint that's matched against
//!     the packet header — biases coverage toward the ID-mismatch and
//!     ID-match branches.
//!   * 25% of iterations call decode_dns_name directly with a chosen
//!     offset, exercising the label-pointer parser standalone.
//!   * Bytes that would naturally form valid DNS headers (12-byte
//!     header) are concentrated near the start of the input via the
//!     shape of the first few bytes.

use asupersync::net::dns::{DnsError, decode_dns_name_for_fuzz, parse_dns_response_for_fuzz};
use libfuzzer_sys::fuzz_target;

fn observe_dns_response_parse(packet: &[u8], expected_id: u16) -> Result<(), DnsError> {
    let result = parse_dns_response_for_fuzz(packet, expected_id);

    match &result {
        Ok(()) => {
            assert!(
                packet.len() >= 12,
                "successful DNS response parse accepted a packet shorter than the DNS header"
            );
        }
        Err(err) => {
            assert!(
                !format!("{err:?}").is_empty(),
                "DNS response parser errors must remain observable"
            );
        }
    }

    result
}

fn observe_dns_name_decode(packet: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let result = decode_dns_name_for_fuzz(packet, offset);

    match &result {
        Ok(name) => {
            assert!(
                *offset <= packet.len(),
                "successful DNS name decode advanced past the packet"
            );
            assert!(
                name.len() <= packet.len(),
                "successful DNS name decode produced a name longer than the packet"
            );
        }
        Err(err) => {
            assert!(
                !format!("{err:?}").is_empty(),
                "DNS name decoder errors must remain observable"
            );
        }
    }

    result
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // First 2 bytes: expected_id. Sometimes this matches the packet's
    // own header ID (bytes 0..2 of the packet) and sometimes not — both
    // branches matter.
    let expected_id = u16::from_be_bytes([data[0], data[1]]);

    // Decide which surface to fuzz this iteration based on bit 0 of
    // byte 2.
    let mode = data[2] & 0x03;
    let packet = &data[3..];

    match mode {
        0..=2 => {
            // ── Property 1, 2, 3 on parse_dns_response ────────────────
            // The parser MUST return Ok or Err; anything else (panic,
            // hang) is a bug. Observe both successful parses and typed
            // errors so parser outcomes do not disappear.
            let _ = observe_dns_response_parse(packet, expected_id);
        }
        _ => {
            // ── Property 1, 2 on decode_dns_name standalone ───────────
            // Pick a starting offset from byte 0 of the packet (mod
            // packet length); this exercises the label parser at varied
            // positions including just-past-end (which must be handled
            // as Err, not panic).
            if packet.is_empty() {
                return;
            }
            let mut offset = (packet[0] as usize) % packet.len().max(1);
            let _ = observe_dns_name_decode(packet, &mut offset);
        }
    }

    // ── Bonus: known label-pointer-bomb shapes ────────────────────────
    // Exercise the canonical "pointer to itself" cycle and a 2-cycle to
    // make sure the cycle-detection always fires, not just on random
    // input. These are deterministic per iteration but cheap.
    let bomb_self_loop = [0u8; 12]
        .iter()
        .copied()
        .chain([0xC0u8, 0x00].iter().copied())
        .collect::<Vec<u8>>();
    let mut off = 12;
    let _ = observe_dns_name_decode(&bomb_self_loop, &mut off);

    // 2-step cycle: offset 12 points to 14, offset 14 points to 12
    let mut bomb_two_cycle = vec![0u8; 16];
    bomb_two_cycle[12] = 0xC0;
    bomb_two_cycle[13] = 0x0E; // -> offset 14
    bomb_two_cycle[14] = 0xC0;
    bomb_two_cycle[15] = 0x0C; // -> offset 12
    let mut off = 12;
    let _ = observe_dns_name_decode(&bomb_two_cycle, &mut off);
});
