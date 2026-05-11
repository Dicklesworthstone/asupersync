#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    bytes::BytesMut,
    http::h2::hpack::{Decoder, Header},
};
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
    assert_block_start_table_size_updates_evict_stale_dynamic_entry();

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

    // 3. Next header block: fuzzed table size update, dynamic table size update 0,
    // then a second update back to the fuzzed size.
    // Then attempt an indexed reference to the previously inserted dynamic entry (index 62)
    // 1011 1110 (0xBE) = Indexed header field 62 (first dynamic entry)
    let mut bad_block = BytesMut::new();

    // Fuzzed pre-shrink update. Consecutive updates are valid at block start.
    let first_size = data.update_1.clamp(0, allowed_size);
    append_dynamic_table_size_update(&mut bad_block, first_size);

    // Shrink to 0, which must evict the dynamic entry inserted above.
    append_dynamic_table_size_update(&mut bad_block, 0);

    // Second update: back to some size
    let size_2 = data.update_2.clamp(0, allowed_size);
    append_dynamic_table_size_update(&mut bad_block, size_2);

    // Then access an index
    let idx = data.accessed_index.clamp(1, 255);
    append_indexed_header(&mut bad_block, idx);

    // Oracle 1: Consecutive dynamic table size updates are only accepted at block start.
    // (Our block above has them at the start, so it should not fail on that specific rule).
    // Oracle 2: The intermediate shrink to 0 is applied before the later grow.
    // Oracle 3: A stale dynamic-table index is rejected after the eviction.
    let mut bad_block_frozen = bad_block.freeze();
    let res2 = decoder.decode(&mut bad_block_frozen);

    // If we accessed index 62 (the dynamic one) and the size was updated to 0 in between,
    // the dynamic table should have been cleared, and index 62 should be invalid!
    if idx == 62 {
        assert!(
            res2.is_err(),
            "Decoder must reject stale dynamic-table index after eviction"
        );
    }

    // Oracle 4: Decoder state remains usable for the next valid block after the rejection path.
    let mut good_block = BytesMut::new();
    good_block.extend_from_slice(&[0x82]); // Index 2 (:method GET)
    let res3 = decoder.decode(&mut good_block.freeze());

    assert!(
        res3.is_ok(),
        "Decoder state must remain usable after rejecting stale index"
    );
});

fn append_dynamic_table_size_update(block: &mut BytesMut, size: usize) {
    if size < 31 {
        block.extend_from_slice(&[0x20 | (size as u8)]);
    } else {
        block.extend_from_slice(&[0x3F]);
        let mut rem = size - 31;
        while rem >= 128 {
            block.extend_from_slice(&[(rem % 128 + 128) as u8]);
            rem /= 128;
        }
        block.extend_from_slice(&[rem as u8]);
    }
}

fn append_indexed_header(block: &mut BytesMut, idx: usize) {
    if idx < 128 {
        block.extend_from_slice(&[0x80 | (idx as u8)]);
    } else {
        block.extend_from_slice(&[0xFF]);
        let mut rem = idx - 127;
        while rem >= 128 {
            block.extend_from_slice(&[(rem % 128 + 128) as u8]);
            rem /= 128;
        }
        block.extend_from_slice(&[rem as u8]);
    }
}

fn assert_block_start_table_size_updates_evict_stale_dynamic_entry() {
    let mut decoder = Decoder::new();
    decoder.set_max_header_list_size(4096);

    let mut insert_block = BytesMut::new();
    insert_block.extend_from_slice(&[0x41, 0x03, b'f', b'o', b'o']);
    decoder
        .decode(&mut insert_block.freeze())
        .expect("seed dynamic :authority entry");

    let mut stale_index_block = BytesMut::new();
    append_dynamic_table_size_update(&mut stale_index_block, 0);
    append_dynamic_table_size_update(&mut stale_index_block, 128);
    append_indexed_header(&mut stale_index_block, 62);

    let err = decoder
        .decode(&mut stale_index_block.freeze())
        .expect_err("stale dynamic-table index must be rejected after eviction");
    assert!(
        err.message.contains("invalid dynamic index"),
        "unexpected stale-index error: {err:?}"
    );

    let mut good_block = BytesMut::new();
    good_block.extend_from_slice(&[0x82]);
    let headers = decoder
        .decode(&mut good_block.freeze())
        .expect("decoder should remain usable after stale-index rejection");
    assert_eq!(headers, vec![Header::new(":method", "GET")]);
}
