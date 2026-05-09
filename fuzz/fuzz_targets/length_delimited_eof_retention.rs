#![no_main]
use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io;

fn observe_decode_result(
    label: &str,
    before_len: usize,
    buf: &BytesMut,
    result: io::Result<Option<BytesMut>>,
) -> io::Result<Option<BytesMut>> {
    assert!(
        buf.len() <= before_len,
        "{label} must not grow the source buffer"
    );

    match &result {
        Ok(Some(frame)) => {
            assert!(
                buf.len() < before_len,
                "{label} returning a frame must consume input"
            );
            assert!(
                frame.len() <= before_len,
                "{label} returned more frame bytes than were available"
            );
        }
        Ok(None) => {}
        Err(err) => {
            assert!(
                !err.to_string().is_empty(),
                "{label} errors must carry an observable description"
            );
        }
    }

    result
}

fn observe_decode(
    codec: &mut LengthDelimitedCodec,
    buf: &mut BytesMut,
) -> io::Result<Option<BytesMut>> {
    let before_len = buf.len();
    let result = codec.decode(buf);
    observe_decode_result("decode", before_len, buf, result)
}

fn observe_decode_eof(
    codec: &mut LengthDelimitedCodec,
    buf: &mut BytesMut,
) -> io::Result<Option<BytesMut>> {
    let before_len = buf.len();
    let result = codec.decode_eof(buf);
    observe_decode_result("decode_eof", before_len, buf, result)
}

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
        .big_endian()
        .new_codec();

    // Case 1: Truncated frame EOF
    let mut buf = BytesMut::new();
    // Length 4
    buf.put_u16(4);
    // Payload 'a', 'b' (missing 2 bytes)
    buf.put_slice(b"ab");

    // 1 & 2. `decode_eof()` on a truncated final frame returns `UnexpectedEof`, no partial frame.
    let res = observe_decode_eof(&mut codec, &mut buf);
    match res {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        _ => panic!("decode_eof on truncated frame should return UnexpectedEof"),
    }

    // 3. The complete header is consumed, but visible partial payload bytes are retained.
    assert_eq!(
        buf.len(),
        2,
        "partial payload should remain buffered after EOF rejection"
    );
    assert_eq!(&buf[..], b"ab");

    // 4. Completing the retained payload later yields exactly the skipped frame bytes.
    buf.put_slice(b"cd"); // complete the frame
    let frame = observe_decode(&mut codec, &mut buf).unwrap().unwrap();
    assert_eq!(frame.as_ref(), b"abcd");
    assert!(buf.is_empty());

    // Case 2: Companion seed with header split
    let mut codec2 = LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_length(2)
        .length_adjustment(0)
        .num_skip(2)
        .max_frame_length(1024)
        .big_endian()
        .new_codec();

    let mut buf2 = BytesMut::new();
    buf2.put_u8(0); // Half of length field

    let res2 = observe_decode_eof(&mut codec2, &mut buf2);
    match res2 {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        _ => panic!("decode_eof on truncated header should return UnexpectedEof"),
    }
    assert_eq!(
        buf2.len(),
        1,
        "buffer should not be consumed for split header"
    );

    buf2.put_u8(4); // Second half of length field
    buf2.put_slice(b"efgh");

    let frame2 = observe_decode(&mut codec2, &mut buf2).unwrap().unwrap();
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
        let fuzzed_builder = LengthDelimitedCodec::builder()
            .length_field_offset(0)
            .length_field_length(length_field_length)
            .length_adjustment(input.length_adjustment as isize)
            .num_skip(input.num_skip as usize)
            .max_frame_length(if input.max_frame_length == 0 {
                1024
            } else {
                input.max_frame_length
            });
        let mut fuzzed_codec = if input.big_endian {
            fuzzed_builder.big_endian().new_codec()
        } else {
            fuzzed_builder.little_endian().new_codec()
        };

        let mut fuzzed_buf = BytesMut::new();
        fuzzed_buf.extend_from_slice(&input.chunk1);
        let _ = observe_decode(&mut fuzzed_codec, &mut fuzzed_buf);
        fuzzed_buf.extend_from_slice(&input.chunk2);
        let _ = observe_decode(&mut fuzzed_codec, &mut fuzzed_buf);
        fuzzed_buf.extend_from_slice(&input.chunk3);
        let _ = observe_decode_eof(&mut fuzzed_codec, &mut fuzzed_buf);
    }
});
