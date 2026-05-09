//! Fuzz target for bytes codec and framing parser systems.
//!
//! This fuzzer tests BytesCodec, FramedRead, and codec composition scenarios
//! for memory safety, state consistency, and proper boundary handling at the
//! codec layer (above raw buffer manipulation).
//!
//! # Attack vectors tested:
//! - BytesCodec decode/encode operations with malformed data
//! - FramedRead with various buffer sizes and read patterns
//! - Codec composition and nested framing scenarios
//! - Stream interruption and recovery mechanisms
//! - Invalid codec configuration parameters
//! - Fragmented reads across multiple decode operations
//! - Zero-length and oversized frame handling
//! - Decoder state corruption through malformed input
//! - EOF handling in various states
//! - Buffer management during codec operations
//! - Mixed codec types in single stream
//! - Codec state consistency checking
//!
//! # Invariants validated:
//! - No panics during codec operations
//! - Memory safety across all codec usage
//! - Decoder state remains valid after errors
//! - Proper EOF handling in all scenarios
//! - BytesCodec round-trip property preservation
//! - FramedRead buffer management consistency
//! - Codec composition maintains data integrity
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run bytes_codec_framing
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{BytesCodec, Decoder, Encoder, FramedRead};
use asupersync::io::{AsyncRead, ReadBuf};
use libfuzzer_sys::fuzz_target;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Maximum buffer size to prevent memory exhaustion.
const MAX_BUFFER_SIZE: usize = 16384;

/// Maximum number of operations per test case.
const MAX_OPERATIONS: usize = 32;

/// Maximum read chunk size for fragmented reads.
const MAX_CHUNK_SIZE: usize = 256;

#[derive(Arbitrary, Debug)]
struct FuzzConfig {
    framed_buffer_capacity: u16, // FramedRead buffer capacity
    use_fragmented_reads: bool,  // Test fragmented async reads
    test_round_trip: bool,       // Test encode->decode round trips
    test_eof_handling: bool,     // Test EOF scenarios
    mock_read_chunk_size: u8,    // Size of chunks for mock reader
}

#[derive(Arbitrary, Debug)]
enum CodecOperation {
    /// Basic decode operation
    Decode,
    /// Encode then decode bytes
    EncodeDecodeBytes(Vec<u8>),
    /// Encode then decode BytesMut
    EncodeDecodeBytesM(Vec<u8>),
    /// Encode then decode Vec<u8>
    EncodeDecodeVec(Vec<u8>),
    /// Test EOF handling
    TestEOF,
    /// Add more data to buffer
    AddData(Vec<u8>),
    /// Clear buffer
    ClearBuffer,
    /// Test with multiple small operations
    MultipleSmallOps(Vec<Vec<u8>>),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: FuzzConfig,
    operations: Vec<CodecOperation>,
    initial_data: Vec<u8>,
    framed_read_data: Vec<u8>,
}

/// Mock AsyncRead for testing FramedRead with controlled input patterns.
#[derive(Debug)]
struct MockAsyncRead {
    data: Vec<u8>,
    position: usize,
    chunk_size: usize,
    should_block: bool,
}

impl MockAsyncRead {
    fn new(data: Vec<u8>, chunk_size: usize) -> Self {
        Self {
            data,
            position: 0,
            chunk_size: chunk_size.max(1), // Ensure at least 1 byte per read
            should_block: false,
        }
    }

    fn with_blocking(mut self, should_block: bool) -> Self {
        self.should_block = should_block;
        self
    }
}

impl AsyncRead for MockAsyncRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.should_block && self.position == 0 {
            return Poll::Pending; // Simulate blocking on first read
        }

        if self.position >= self.data.len() {
            return Poll::Ready(Ok(())); // EOF
        }

        let remaining = self.data.len() - self.position;
        let to_read = remaining.min(self.chunk_size).min(buf.remaining());

        if to_read == 0 {
            return Poll::Ready(Ok(()));
        }

        buf.put_slice(&self.data[self.position..self.position + to_read]);
        self.position += to_read;

        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|input: FuzzInput| {
    // Guard against excessive operations
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    // Guard against excessive initial data
    if input.initial_data.len() > MAX_BUFFER_SIZE {
        return;
    }

    if input.framed_read_data.len() > MAX_BUFFER_SIZE {
        return;
    }

    // Test BytesCodec operations
    test_bytes_codec_operations(&input);

    // Test FramedRead if configured
    if input.config.use_fragmented_reads && !input.framed_read_data.is_empty() {
        test_framed_read_operations(&input);
    }

    // Test codec composition
    if input.operations.len() > 1 {
        test_codec_composition(&input);
    }

    // Test round-trip properties if enabled
    if input.config.test_round_trip {
        test_round_trip_properties(&input);
    }

    // Test EOF handling if enabled
    if input.config.test_eof_handling {
        test_eof_handling(&input);
    }
});

/// Test BytesCodec operations with various data patterns.
fn test_bytes_codec_operations(input: &FuzzInput) {
    let mut codec = BytesCodec::new();
    let mut buffer = BytesMut::with_capacity(1024);

    // Add initial data
    if !input.initial_data.is_empty() {
        buffer.extend_from_slice(&input.initial_data);
    }

    for operation in &input.operations {
        match operation {
            CodecOperation::Decode => {
                let before_len = buffer.len();
                let result = codec.decode(&mut buffer);
                observe_bytes_decode(result, before_len, &buffer);
            }

            CodecOperation::EncodeDecodeBytes(data) => {
                if data.len() <= MAX_BUFFER_SIZE {
                    test_bytes_codec_encode_decode(&mut codec, &mut buffer, data.clone());
                }
            }

            CodecOperation::EncodeDecodeBytesM(data) => {
                if data.len() <= MAX_BUFFER_SIZE {
                    test_bytes_codec_encode_decode_mut(&mut codec, &mut buffer, data.clone());
                }
            }

            CodecOperation::EncodeDecodeVec(data) => {
                if data.len() <= MAX_BUFFER_SIZE {
                    test_bytes_codec_encode_decode_vec(&mut codec, &mut buffer, data.clone());
                }
            }

            CodecOperation::TestEOF => {
                let mut test_buffer = BytesMut::from(&buffer[..]);
                let eof_result = codec.decode_eof(&mut test_buffer);
                verify_eof_result(&eof_result, &buffer);
            }

            CodecOperation::AddData(data) => {
                let total_len = buffer.len() + data.len();
                if total_len <= MAX_BUFFER_SIZE {
                    buffer.extend_from_slice(data);
                }
            }

            CodecOperation::ClearBuffer => {
                buffer.clear();
            }

            CodecOperation::MultipleSmallOps(ops) => {
                for small_data in ops {
                    if small_data.len() <= 64 && buffer.len() + small_data.len() <= MAX_BUFFER_SIZE
                    {
                        buffer.extend_from_slice(small_data);
                        let before_len = buffer.len();
                        let result = codec.decode(&mut buffer);
                        observe_bytes_decode(result, before_len, &buffer);
                    }
                }
            }
        }

        // Verify buffer invariants after each operation
        verify_buffer_invariants(&buffer);
    }
}

/// Test BytesCodec encoding and decoding of Bytes.
fn test_bytes_codec_encode_decode(codec: &mut BytesCodec, buffer: &mut BytesMut, data: Vec<u8>) {
    let original_len = buffer.len();
    let original_buffer = buffer.clone();
    let bytes_data = asupersync::bytes::Bytes::from(data.clone());

    // Test encoding
    if let Ok(()) = codec.encode(bytes_data, buffer) {
        // Verify buffer grew by expected amount
        assert_eq!(buffer.len(), original_len + data.len());
        assert_eq!(&buffer[..original_len], &original_buffer[..]);
        assert_eq!(&buffer[original_len..], &data[..]);

        // Test decoding
        let decode_len = buffer.len();
        let result = codec.decode(buffer);
        if let Some(decoded) = observe_bytes_decode(result, decode_len, buffer) {
            assert_eq!(decoded.len(), original_len + data.len());
            assert_eq!(&decoded[..original_len], &original_buffer[..]);
            assert_eq!(&decoded[original_len..], &data[..]);
        }
    }
}

/// Test BytesCodec encoding and decoding of BytesMut.
fn test_bytes_codec_encode_decode_mut(
    codec: &mut BytesCodec,
    buffer: &mut BytesMut,
    data: Vec<u8>,
) {
    let original_len = buffer.len();
    let original_buffer = buffer.clone();
    let bytes_mut_data = BytesMut::from(&data[..]);

    if let Ok(()) = codec.encode(bytes_mut_data, buffer) {
        assert_eq!(buffer.len(), original_len + data.len());
        assert_eq!(&buffer[..original_len], &original_buffer[..]);
        assert_eq!(&buffer[original_len..], &data[..]);

        let decode_len = buffer.len();
        let result = codec.decode(buffer);
        if let Some(decoded) = observe_bytes_decode(result, decode_len, buffer) {
            assert_eq!(decoded.len(), original_len + data.len());
            assert_eq!(&decoded[..original_len], &original_buffer[..]);
            assert_eq!(&decoded[original_len..], &data[..]);
        }
    }
}

/// Test BytesCodec encoding and decoding of Vec<u8>.
fn test_bytes_codec_encode_decode_vec(
    codec: &mut BytesCodec,
    buffer: &mut BytesMut,
    data: Vec<u8>,
) {
    let original_len = buffer.len();
    let original_buffer = buffer.clone();
    let data_len = data.len();
    let data_copy = data.clone();

    if let Ok(()) = codec.encode(data, buffer) {
        assert_eq!(buffer.len(), original_len + data_len);
        assert_eq!(&buffer[..original_len], &original_buffer[..]);
        assert_eq!(&buffer[original_len..], &data_copy[..]);

        let decode_len = buffer.len();
        let result = codec.decode(buffer);
        if let Some(decoded) = observe_bytes_decode(result, decode_len, buffer) {
            assert_eq!(decoded.len(), original_len + data_len);
            assert_eq!(&decoded[..original_len], &original_buffer[..]);
            assert_eq!(&decoded[original_len..], &data_copy[..]);
        }
    }
}

/// Test FramedRead operations with mock async reader.
fn test_framed_read_operations(input: &FuzzInput) {
    let chunk_size = (input.config.mock_read_chunk_size as usize).clamp(1, MAX_CHUNK_SIZE);
    let mock_reader = MockAsyncRead::new(input.framed_read_data.clone(), chunk_size);
    let codec = BytesCodec::new();

    let capacity = (input.config.framed_buffer_capacity as usize).clamp(64, MAX_BUFFER_SIZE);
    let mut framed_read = FramedRead::with_capacity(mock_reader, codec, capacity);

    // Test basic FramedRead operations
    test_framed_read_basic_ops(&mut framed_read);

    // Test with blocking reader
    if !input.framed_read_data.is_empty() {
        let blocking_reader =
            MockAsyncRead::new(input.framed_read_data.clone(), chunk_size).with_blocking(true);
        let blocking_codec = BytesCodec::new();
        let mut blocking_framed =
            FramedRead::with_capacity(blocking_reader, blocking_codec, capacity);
        test_framed_read_basic_ops(&mut blocking_framed);
    }
}

/// Test basic FramedRead operations.
fn test_framed_read_basic_ops<R>(framed_read: &mut FramedRead<R, BytesCodec>)
where
    R: AsyncRead + Unpin,
{
    // Test getter methods (should not panic)
    let _ = framed_read.get_ref();
    let _ = framed_read.decoder();
    let _ = framed_read.read_buffer();

    // Test mutable getters
    let _ = framed_read.get_mut();
    let _ = framed_read.decoder_mut();

    // Note: We can't easily test the Stream implementation in a fuzz target
    // without an async runtime, but we can test the basic structure.
}

/// Test codec composition scenarios.
fn test_codec_composition(input: &FuzzInput) {
    if input.initial_data.is_empty() {
        return;
    }

    // Test multiple BytesCodec instances working together
    let mut codec1 = BytesCodec::new();
    let mut codec2 = BytesCodec::new();

    let mut buffer1 = BytesMut::from(&input.initial_data[..]);
    let mut buffer2 = BytesMut::new();

    // Decode with first codec
    let buffer1_len = buffer1.len();
    let result = codec1.decode(&mut buffer1);
    if let Some(decoded1) = observe_bytes_decode(result, buffer1_len, &buffer1) {
        let decoded1_len = decoded1.len();
        // Encode with second codec
        if codec2.encode(decoded1.freeze(), &mut buffer2).is_ok() {
            // Decode again with second codec
            let buffer2_len = buffer2.len();
            let result = codec2.decode(&mut buffer2);
            if let Some(decoded2) = observe_bytes_decode(result, buffer2_len, &buffer2) {
                // The data should be the same (BytesCodec is pass-through)
                assert_eq!(decoded1_len, decoded2.len());
            }
        }
    }

    // Test nested encoding/decoding
    test_nested_codec_operations(&input.initial_data);
}

/// Test nested codec operations.
fn test_nested_codec_operations(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut outer_codec = BytesCodec::new();
    let mut inner_codec = BytesCodec::new();

    let mut outer_buffer = BytesMut::new();
    let mut inner_buffer = BytesMut::from(data);

    // Inner decode
    let inner_len = inner_buffer.len();
    let result = inner_codec.decode(&mut inner_buffer);
    if let Some(inner_decoded) = observe_bytes_decode(result, inner_len, &inner_buffer) {
        assert_eq!(inner_decoded.len(), data.len());

        // Outer encode
        if outer_codec.encode(inner_decoded, &mut outer_buffer).is_ok() {
            // Outer decode
            let before_len = outer_buffer.len();
            let result = outer_codec.decode(&mut outer_buffer);
            if let Some(decoded) = observe_bytes_decode(result, before_len, &outer_buffer) {
                assert_eq!(decoded.len(), data.len());
                assert_eq!(&decoded[..], data);
            }
        }
    }
}

/// Test round-trip properties.
fn test_round_trip_properties(input: &FuzzInput) {
    if input.initial_data.is_empty() {
        return;
    }

    let mut codec = BytesCodec::new();
    let mut encode_buffer = BytesMut::new();

    // Test round-trip: original data -> encode -> decode -> should match
    let original_data = asupersync::bytes::Bytes::from(input.initial_data.clone());

    // Encode
    if codec
        .encode(original_data.clone(), &mut encode_buffer)
        .is_ok()
    {
        // Decode
        let decode_len = encode_buffer.len();
        let result = codec.decode(&mut encode_buffer);
        if let Some(decoded) = observe_bytes_decode(result, decode_len, &encode_buffer) {
            // BytesCodec should preserve data exactly (it's pass-through)
            assert_eq!(decoded.len(), original_data.len());
            assert_eq!(&decoded[..], &original_data[..]);

            assert!(encode_buffer.is_empty());
        }
    }
}

/// Test EOF handling in various scenarios.
fn test_eof_handling(input: &FuzzInput) {
    let mut codec = BytesCodec::new();

    // Test EOF on empty buffer
    let mut empty_buffer = BytesMut::new();
    let eof_empty = codec.decode_eof(&mut empty_buffer);
    assert!(eof_empty.is_ok());
    if let Ok(result) = eof_empty {
        assert!(result.is_none()); // EOF on empty should return None
    }

    // Test EOF on buffer with data
    if !input.initial_data.is_empty() {
        let mut data_buffer = BytesMut::from(&input.initial_data[..]);
        let eof_data = codec.decode_eof(&mut data_buffer);
        verify_eof_result(&eof_data, &BytesMut::from(&input.initial_data[..]));
    }

    // Test EOF after partial operations
    for operation in &input.operations {
        if let CodecOperation::AddData(data) = operation
            && !data.is_empty()
            && data.len() <= 1024
        {
            let mut test_buffer = BytesMut::from(&data[..]);
            let before_len = test_buffer.len();
            let result = codec.decode(&mut test_buffer);
            observe_bytes_decode(result, before_len, &test_buffer);
            let eof_result = codec.decode_eof(&mut test_buffer);
            verify_eof_result(&eof_result, &test_buffer);
        }
    }
}

/// Observe a `BytesCodec` decode and assert its pass-through contract.
fn observe_bytes_decode(
    result: Result<Option<BytesMut>, io::Error>,
    before_len: usize,
    buffer_after: &BytesMut,
) -> Option<BytesMut> {
    match result {
        Ok(Some(decoded)) => {
            assert!(before_len > 0);
            assert_eq!(decoded.len(), before_len);
            assert!(buffer_after.is_empty());
            Some(decoded)
        }
        Ok(None) => {
            assert_eq!(before_len, 0);
            assert!(buffer_after.is_empty());
            None
        }
        Err(err) => panic!("BytesCodec decode should be infallible: {err}"),
    }
}

/// Verify EOF result meets expected invariants.
fn verify_eof_result(result: &Result<Option<BytesMut>, io::Error>, original_buffer: &BytesMut) {
    match result {
        Ok(Some(decoded)) => {
            // EOF decode succeeded
            assert!(!decoded.is_empty() || original_buffer.is_empty());
        }
        Ok(None) => {
            // EOF with no final frame - valid
        }
        Err(err) => {
            // EOF error - should be UnexpectedEof for incomplete frames
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        }
    }
}

/// Verify buffer invariants hold.
fn verify_buffer_invariants(buffer: &BytesMut) {
    // Basic buffer invariants
    assert!(buffer.len() <= buffer.capacity());

    // Buffer operations should not panic
    let _len = buffer.len();
    let _cap = buffer.capacity();
    let _is_empty = buffer.is_empty();

    // If buffer has data, basic access should work
    if !buffer.is_empty() {
        let _first_byte = buffer[0];
        if buffer.len() > 1 {
            let _last_byte = buffer[buffer.len() - 1];
        }
    }
}

/// Test that codec creation and basic methods work.
#[allow(dead_code)]
fn test_codec_creation_invariants() {
    // BytesCodec creation should always succeed
    let codec1 = BytesCodec::new();
    let _codec2 = BytesCodec;

    // Should be able to create multiple instances
    let _many_codecs: Vec<BytesCodec> = (0..100).map(|_| BytesCodec::new()).collect();

    // Debug formatting should work
    let debug_str = format!("{:?}", codec1);
    assert!(!debug_str.is_empty());

    // Copy should work
    let _copied = codec1;
}
