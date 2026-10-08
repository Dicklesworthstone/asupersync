//! br-asupersync-dycth8 H1: an HPACK header list is never decoded past
//! 16 MiB, even when the configured list size is "unlimited" (`u32::MAX`, which
//! gRPC's `max_metadata_size(0)` maps to). An indexed field costs one octet on
//! the wire but decodes to a full copy of a dynamic-table entry, so a 4 KB
//! entry referenced from a few kilobytes of block used to decode to gigabytes.

use asupersync::bytes::Bytes;
use asupersync::http::h2::HpackDecoder;

const CEILING: usize = 16 * 1024 * 1024;
/// RFC 7541 section 4.1 size of the `x-big` entry with a 4000-octet value.
const ENTRY_SIZE: usize = "x-big".len() + 4000 + 32;

/// An HPACK integer with an `prefix_bits`-bit prefix (RFC 7541 section 5.1).
fn integer(out: &mut Vec<u8>, mut value: usize, prefix_bits: u32, flags: u8) {
    let max = (1_usize << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    value -= max;
    while value >= 128 {
        out.push((value % 128) as u8 | 0x80);
        value /= 128;
    }
    out.push(value as u8);
}

/// A literal `x-big` field with incremental indexing (it becomes dynamic
/// entry 62), followed by `references` one-octet references to it (0xBE is
/// an indexed field, 0x80, for index 62).
fn block(value_len: usize, references: usize) -> Bytes {
    let mut out = vec![0x40, 5];
    out.extend_from_slice(b"x-big");
    integer(&mut out, value_len, 7, 0);
    out.extend(std::iter::repeat_n(b'v', value_len));
    out.extend(std::iter::repeat_n(0xBE, references));
    Bytes::from(out)
}

#[test]
fn an_unlimited_header_list_stops_at_the_decoded_ceiling() {
    let mut decoder = HpackDecoder::new();
    decoder.set_max_header_list_size(u32::MAX as usize);
    let mut src = block(4000, CEILING / ENTRY_SIZE + 1);
    assert!(
        decoder.decode(&mut src).is_err(),
        "a block decoding past 16 MiB is refused"
    );

    // The same shape below the ceiling decodes, so the ceiling is what
    // refused the large block.
    let mut decoder = HpackDecoder::new();
    decoder.set_max_header_list_size(u32::MAX as usize);
    let mut src = block(4000, 100);
    let headers = decoder.decode(&mut src).expect("101 fields fit");
    assert_eq!(headers.len(), 101);
    assert!(headers.iter().all(|header| header.value.len() == 4000));
}

#[test]
fn a_reference_over_the_remaining_budget_is_refused_and_leaves_the_table_intact() {
    let mut decoder = HpackDecoder::new();
    decoder.set_max_header_list_size(16_384);
    let mut src = block(500, 0);
    assert_eq!(decoder.decode(&mut src).expect("entry fits").len(), 1);

    decoder.set_max_header_list_size(100);
    let mut src = Bytes::from(vec![0xBE]);
    assert!(decoder.decode(&mut src).is_err());

    decoder.set_max_header_list_size(16_384);
    let mut src = Bytes::from(vec![0xBE]);
    let headers = decoder.decode(&mut src).expect("reference decodes");
    assert_eq!(headers[0].name, "x-big");
    assert_eq!(headers[0].value.len(), 500);
}
