#![no_main]
use libfuzzer_sys::fuzz_target;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use arbitrary::Arbitrary;
use std::io;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // 2-byte BE length field, 4 bytes payload expected, EOF before the last 2 payload bytes
    // We will supply bytes directly to the codec.
    chunk1: Vec<u8>,
    chunk2: Vec<u8>,
    chunk3: Vec<u8>,
    num_skip: u16,
    length_field_length: u8,
    length_adjustment: i16,
    max_frame_length: usize,
    big_endian: bool,
}

fuzz_target!(|data: &[u8]| {
    // We'll write a manual test specifically tailored to the oracle, rather than using arbitrary data,
    // to strictly enforce the EOF retention logic described in the bead.
    
    // Concrete corpus seed case:
    // - 2-byte BE length field declaring payload length 4
    // - payload bytes 'a', 'b' present
    // - EOF before the final 2 payload bytes.
    // - num_skip = header_len

    let mut codec = LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_length(2)
        .length_adjustment(0)
        .num_skip(2)
        .max_frame_length(1024)
        .big_endian(true)
        .new_codec();

    // Case 1: Truncated frame EOF
    let mut buf = BytesMut::new();
    // Length 4
    buf.put_u16(4);
    // Payload 'a', 'b' (missing 2 bytes)
    buf.put_slice(b"ab");

    // 1 & 2. `decode_eof()` on a truncated final frame returns `UnexpectedEof`, no partial frame.
    let res = codec.decode_eof(&mut buf);
    match res {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        _ => panic!("decode_eof on truncated frame should return UnexpectedEof"),
    }
    
    // 3. Prefix/header bytes remain unconsumed until a full frame exists.
    assert_eq!(buf.len(), 4, "buffer should not be consumed");
    assert_eq!(&buf[..], &[0, 4, b'a', b'b']);

    // 4. Completing the retained prefix later yields exactly the skipped frame bytes.
    buf.put_slice(b"cd"); // complete the frame
    let frame = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(frame.as_ref(), b"abcd");
    assert!(buf.is_empty());


    // Case 2: Companion seed with header split
    let mut codec2 = LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_length(2)
        .length_adjustment(0)
        .num_skip(2)
        .max_frame_length(1024)
        .big_endian(true)
        .new_codec();

    let mut buf2 = BytesMut::new();
    buf2.put_u8(0); // Half of length field
    
    let res2 = codec2.decode_eof(&mut buf2);
    match res2 {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        _ => panic!("decode_eof on truncated header should return UnexpectedEof"),
    }
    assert_eq!(buf2.len(), 1, "buffer should not be consumed for split header");
    
    buf2.put_u8(4); // Second half of length field
    buf2.put_slice(b"efgh");
    
    let frame2 = codec2.decode(&mut buf2).unwrap().unwrap();
    assert_eq!(frame2.as_ref(), b"efgh");
    assert!(buf2.is_empty());


    // Case 3: Fuzz with arbitrary chunks to ensure we don't crash
    if let Ok(input) = FuzzInput::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        let length_field_length = match input.length_field_length % 4 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let mut fuzzed_codec = LengthDelimitedCodec::builder()
            .length_field_offset(0)
            .length_field_length(length_field_length)
            .length_adjustment(input.length_adjustment as isize)
            .num_skip(input.num_skip as usize)
            .max_frame_length(if input.max_frame_length == 0 { 1024 } else { input.max_frame_length })
            .big_endian(input.big_endian)
            .new_codec();

        let mut fuzzed_buf = BytesMut::new();
        fuzzed_buf.extend_from_slice(&input.chunk1);
        let _ = fuzzed_codec.decode(&mut fuzzed_buf);
        fuzzed_buf.extend_from_slice(&input.chunk2);
        let _ = fuzzed_codec.decode(&mut fuzzed_buf);
        fuzzed_buf.extend_from_slice(&input.chunk3);
        let _ = fuzzed_codec.decode_eof(&mut fuzzed_buf);
    }
});
