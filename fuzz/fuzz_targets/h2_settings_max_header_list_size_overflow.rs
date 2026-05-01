#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{Frame, HeadersFrame, Setting, SettingsFrame};
use asupersync::http::h2::settings::Settings;
use libfuzzer_sys::fuzz_target;
use std::panic::{catch_unwind, AssertUnwindSafe};

const MAX_HEADER_LIST_SIZE_2_31: u32 = 0x8000_0000;
const MAX_PARTIAL_VALUE_BYTES: usize = 64;

#[derive(Debug, Arbitrary)]
struct MaxHeaderListOverflowInput {
    stream_seed: u32,
    extra_claimed_bytes: u16,
    literal_form: LiteralForm,
    partial_value: Vec<u8>,
    end_stream: bool,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum LiteralForm {
    WithoutIndexing,
    NeverIndexed,
    IncrementalIndexing,
}

fuzz_target!(|input: MaxHeaderListOverflowInput| {
    let mut local = Settings::server();
    local.max_header_list_size = MAX_HEADER_LIST_SIZE_2_31;
    let mut conn = Connection::server(local);

    let peer_settings = Frame::Settings(SettingsFrame::new(vec![Setting::MaxHeaderListSize(
        MAX_HEADER_LIST_SIZE_2_31,
    )]));
    conn.process_frame(peer_settings)
        .expect("2^31 MAX_HEADER_LIST_SIZE setting should be accepted");
    assert_eq!(
        conn.remote_settings().max_header_list_size,
        MAX_HEADER_LIST_SIZE_2_31
    );

    let claimed_value_len = usize::try_from(MAX_HEADER_LIST_SIZE_2_31)
        .expect("fuzz target requires usize >= u32")
        + usize::from(input.extra_claimed_bytes)
        + 1;
    let header_block = oversized_hpack_literal(
        input.literal_form,
        claimed_value_len,
        &input.partial_value[..input.partial_value.len().min(MAX_PARTIAL_VALUE_BYTES)],
    );
    let headers = Frame::Headers(HeadersFrame::new(
        odd_client_stream_id(input.stream_seed),
        header_block,
        input.end_stream,
        true,
    ));

    let result = catch_unwind(AssertUnwindSafe(|| conn.process_frame(headers)));
    let Err(err) = result.expect("oversized 2^31+ HEADERS block must not panic") else {
        panic!("oversized 2^31+ HEADERS block must fail closed");
    };
    assert_eq!(
        err.code,
        ErrorCode::CompressionError,
        "oversized HPACK literal must close the connection with COMPRESSION_ERROR, not overflow"
    );
});

fn oversized_hpack_literal(form: LiteralForm, claimed_value_len: usize, partial: &[u8]) -> Bytes {
    let mut block = BytesMut::new();
    match form {
        LiteralForm::WithoutIndexing => encode_hpack_integer(&mut block, 4, 4, 0x00),
        LiteralForm::NeverIndexed => encode_hpack_integer(&mut block, 4, 4, 0x10),
        LiteralForm::IncrementalIndexing => encode_hpack_integer(&mut block, 4, 6, 0x40),
    }
    encode_hpack_integer(&mut block, claimed_value_len, 7, 0x00);
    block.extend_from_slice(partial);
    block.freeze()
}

fn encode_hpack_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1usize << prefix_bits) - 1;
    if value < max_first {
        dst.extend_from_slice(&[prefix | value as u8]);
        return;
    }

    dst.extend_from_slice(&[prefix | max_first as u8]);
    let mut remaining = value - max_first;
    while remaining >= 128 {
        dst.extend_from_slice(&[((remaining & 0x7f) as u8) | 0x80]);
        remaining >>= 7;
    }
    dst.extend_from_slice(&[remaining as u8]);
}

fn odd_client_stream_id(seed: u32) -> u32 {
    let id = seed | 1;
    if id == u32::MAX {
        1
    } else {
        id & 0x7fff_ffff
    }
}
