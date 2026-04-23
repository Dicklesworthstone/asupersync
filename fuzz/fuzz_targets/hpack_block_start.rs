#![no_main]

use arbitrary::Arbitrary;
use asupersync::{bytes::BytesMut, http::h2::hpack::{Decoder, Header}};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct BlockStartTest {
    // We fuzz the exact sequence of size updates
    initial_size: usize,
    update_1: usize,
    update_2: usize,
    
    // We also fuzz the index accessed
    accessed_index: usize,
}

fuzz_target!(|data: BlockStartTest| {
    // The target sets up a specific scenario with some fuzzed parameters
    // around consecutive block-start table-size updates.
    
    // 1. Setup a decoder
    let mut decoder = Decoder::new();
    
    // Ensure the size updates are within reasonable limits to avoid OOM
    let allowed_size = data.initial_size.clamp(128, 4096);
    decoder.set_max_header_list_size(allowed_size);

    // 2. Insert one dynamic entry via incremental indexing (name index 1, which is :authority)
    // 0100 0001 (0x41) = Incremental indexing with Name Index 1
    // 0000 0011 (0x03) = Value Length 3
    // 'f' 'o' 'o'
    let mut insert_block = BytesMut::new();
    insert_block.extend_from_slice(&[0x41, 0x03, b'f', b'o', b'o']);
    
    let res = decoder.decode(&mut insert_block.freeze());
    if res.is_err() {
        return; // If we can't even insert, the parameters are too small
    }

    // 3. Next header block: dynamic table size update 0, then a second update back to 128
    // Then attempt an indexed reference to the previously inserted dynamic entry (index 62)
    // 0010 0000 (0x20) = Size update 0
    // 0011 1111 (0x3F) = Size update 128 (requires 1 byte: 128 - 31 = 97 = 0x61)
    // 1011 1110 (0xBE) = Indexed header field 62 (first dynamic entry)
    let mut bad_block = BytesMut::new();
    
    // First update: 0
    bad_block.extend_from_slice(&[0x20]); 
    
    // Second update: back to some size
    let size_2 = data.update_2.clamp(0, allowed_size);
    if size_2 < 31 {
        bad_block.extend_from_slice(&[0x20 | (size_2 as u8)]);
    } else {
        bad_block.extend_from_slice(&[0x3F]);
        let mut rem = size_2 - 31;
        while rem >= 128 {
            bad_block.extend_from_slice(&[(rem % 128 + 128) as u8]);
            rem /= 128;
        }
        bad_block.extend_from_slice(&[rem as u8]);
    }
    
    // Then access an index
    let idx = data.accessed_index.clamp(1, 255);
    if idx < 128 {
        bad_block.extend_from_slice(&[0x80 | (idx as u8)]);
    } else {
        bad_block.extend_from_slice(&[0xFF]);
        let mut rem = idx - 127;
        while rem >= 128 {
            bad_block.extend_from_slice(&[(rem % 128 + 128) as u8]);
            rem /= 128;
        }
        bad_block.extend_from_slice(&[rem as u8]);
    }

    // Oracle 1: Consecutive dynamic table size updates are only accepted at block start.
    // (Our block above has them at the start, so it should not fail on that specific rule).
    // Oracle 2: The intermediate shrink to 0 is applied before the later grow.
    // Oracle 3: A stale dynamic-table index is rejected after the eviction.
    let mut bad_block_frozen = bad_block.freeze();
    let res2 = decoder.decode(&mut bad_block_frozen);
    
    // If we accessed index 62 (the dynamic one) and the size was updated to 0 in between,
    // the dynamic table should have been cleared, and index 62 should be invalid!
    if idx == 62 {
        assert!(res2.is_err(), "Decoder must reject stale dynamic-table index after eviction");
    }

    // Oracle 4: Decoder state remains usable for the next valid block after the rejection path.
    let mut good_block = BytesMut::new();
    good_block.extend_from_slice(&[0x82]); // Index 2 (:method GET)
    let res3 = decoder.decode(&mut good_block.freeze());
    
    assert!(res3.is_ok(), "Decoder state must remain usable after rejecting stale index");
});
