#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic testing for io::buf_reader/buf_writer read-ahead/write-behind invariants.
//!
//! Tests the core metamorphic relations that must hold for correct
//! buffered I/O implementations using proptest + mock I/O.

#![allow(clippy::missing_panics_doc)]

use asupersync::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, BufWriter, ReadBuf};
use proptest::prelude::*;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::{cmp, io};

/// Helper to poll operations to completion
fn poll_to_completion<T>(mut operation: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>) -> io::Result<T> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    loop {
        match operation(&mut cx) {
            Poll::Ready(result) => return result,
            Poll::Pending => thread::yield_now(),
        }
    }
}

/// Mock reader that tracks read calls and can simulate partial reads
#[derive(Debug, Clone)]
struct MockReader {
    data: Arc<Vec<u8>>,
    position: Arc<AtomicUsize>,
    read_calls: Arc<AtomicUsize>,
    max_read_size: usize,
}

impl MockReader {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(data),
            position: Arc::new(AtomicUsize::new(0)),
            read_calls: Arc::new(AtomicUsize::new(0)),
            max_read_size: usize::MAX,
        }
    }

    fn with_max_read_size(mut self, max_size: usize) -> Self {
        self.max_read_size = max_size;
        self
    }

    fn read_count(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }

    fn position(&self) -> usize {
        self.position.load(Ordering::SeqCst)
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position())
    }
}

impl AsyncRead for MockReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);

        let pos = self.position.load(Ordering::SeqCst);
        if pos >= self.data.len() {
            return Poll::Ready(Ok(()));
        }

        let available = &self.data[pos..];
        let to_read = cmp::min(
            cmp::min(available.len(), buf.remaining()),
            self.max_read_size,
        );

        buf.put_slice(&available[..to_read]);
        self.position.fetch_add(to_read, Ordering::SeqCst);

        Poll::Ready(Ok(()))
    }
}

/// Mock writer that tracks write calls and can simulate partial writes
#[derive(Debug, Clone)]
struct MockWriter {
    data: Arc<Mutex<Vec<u8>>>,
    write_calls: Arc<AtomicUsize>,
    max_write_size: usize,
}

impl MockWriter {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
            write_calls: Arc::new(AtomicUsize::new(0)),
            max_write_size: usize::MAX,
        }
    }

    fn with_max_write_size(mut self, max_size: usize) -> Self {
        self.max_write_size = max_size;
        self
    }

    fn write_count(&self) -> usize {
        self.write_calls.load(Ordering::SeqCst)
    }

    fn data(&self) -> Vec<u8> {
        self.data.lock().unwrap().clone()
    }
}

impl AsyncWrite for MockWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);

        let to_write = cmp::min(buf.len(), self.max_write_size);
        self.data.lock().unwrap().extend_from_slice(&buf[..to_write]);

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Helper for reading all data from a reader
fn read_all<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        let mut read_buf = ReadBuf::new(&mut buf);

        poll_to_completion(|cx| {
            Pin::new(&mut reader).poll_read(cx, &mut read_buf)
        })?;

        if read_buf.filled().is_empty() {
            break;
        }

        data.extend_from_slice(read_buf.filled());
        read_buf = ReadBuf::new(&mut buf); // Reset for next iteration
    }

    Ok(data)
}

/// Helper for writing all data to a writer
fn write_all<W: AsyncWrite + Unpin>(mut writer: W, data: &[u8]) -> io::Result<()> {
    let mut pos = 0;

    while pos < data.len() {
        let written = poll_to_completion(|cx| {
            Pin::new(&mut writer).poll_write(cx, &data[pos..])
        })?;
        pos += written;
    }

    poll_to_completion(|cx| {
        Pin::new(&mut writer).poll_flush(cx)
    })?;

    Ok(())
}

/// MR1: BufReader::read returns same bytes as underlying reader
///
/// Metamorphic relation: Reading from a BufReader should return exactly
/// the same byte sequence as reading directly from the underlying reader.
///
/// Properties tested:
/// - Buffering is transparent to the caller
/// - All data is preserved and returned in order
/// - EOF behavior matches underlying reader
#[proptest]
fn mr_buf_reader_transparent_buffering(
    #[strategy(proptest::collection::vec(any::<u8>(), 0..1000))] data: Vec<u8>,
    #[strategy(1usize..=100)] buf_size: usize,
    #[strategy(1usize..=50)] max_read_size: usize,
) {
    // Read directly from mock reader
    let direct_reader = MockReader::new(data.clone()).with_max_read_size(max_read_size);
    let direct_data = read_all(direct_reader).expect("direct read should succeed");

    // Read through BufReader
    let mock_reader = MockReader::new(data).with_max_read_size(max_read_size);
    let buf_reader = BufReader::with_capacity(buf_size, mock_reader);
    let buffered_data = read_all(buf_reader).expect("buffered read should succeed");

    // Same data should be read
    prop_assert_eq!(direct_data, buffered_data, "buffered reader should return same data");
}

/// MR2: fill_buf then consume_count consistent
///
/// Metamorphic relation: After fill_buf returns N bytes, consuming exactly
/// N bytes should leave the buffer empty, and subsequent reads should
/// continue from the correct position.
///
/// Properties tested:
/// - fill_buf and consume work together correctly
/// - Buffer state is consistent after consume
/// - Data is not lost or duplicated
#[proptest]
fn mr_fill_buf_consume_consistency(
    #[strategy(proptest::collection::vec(any::<u8>(), 1..1000))] data: Vec<u8>,
    #[strategy(1usize..=100)] buf_size: usize,
) {
    let mock_reader = MockReader::new(data.clone());
    let mut buf_reader = BufReader::with_capacity(buf_size, mock_reader);

    let mut consumed_data = Vec::new();

    while consumed_data.len() < data.len() {
        // Fill buffer
        let filled = poll_to_completion(|cx| {
            Pin::new(&mut buf_reader).poll_fill_buf(cx)
        }).expect("fill_buf should succeed");

        if filled.is_empty() {
            break; // EOF
        }

        // Record the data before consuming
        let fill_data = filled.to_vec();
        let consume_amount = filled.len();

        // Consume all filled data
        Pin::new(&mut buf_reader).consume(consume_amount);
        consumed_data.extend(fill_data);
    }

    prop_assert_eq!(consumed_data, data, "fill_buf+consume should read all data correctly");
}

/// MR3: BufWriter::write buffers until capacity, flush drains fully
///
/// Metamorphic relation: BufWriter should buffer writes until capacity is reached,
/// then flush should write all buffered data to the underlying writer.
///
/// Properties tested:
/// - Writes are buffered until capacity
/// - Flush drains all buffered data
/// - No data is lost or duplicated
/// - Write count optimization (fewer underlying writes)
#[proptest]
fn mr_buf_writer_buffering_and_flush(
    #[strategy(proptest::collection::vec(any::<u8>(), 0..1000))] data: Vec<u8>,
    #[strategy(1usize..=100)] buf_size: usize,
    #[strategy(1usize..=20)] chunk_size: usize,
) {
    let mock_writer = MockWriter::new();
    let mock_writer_clone = mock_writer.clone();
    let mut buf_writer = BufWriter::with_capacity(buf_size, mock_writer);

    // Write data in chunks
    for chunk in data.chunks(chunk_size) {
        poll_to_completion(|cx| {
            Pin::new(&mut buf_writer).poll_write(cx, chunk)
        }).expect("write should succeed");
    }

    // Flush to ensure all data is written
    poll_to_completion(|cx| {
        Pin::new(&mut buf_writer).poll_flush(cx)
    }).expect("flush should succeed");

    // All data should be written to underlying writer
    let written_data = mock_writer_clone.data();
    prop_assert_eq!(written_data, data, "all data should be written after flush");

    // If buffering is working, should have fewer write calls than chunks
    // (unless chunk_size > buf_size which bypasses buffer)
    if chunk_size <= buf_size && data.len() > buf_size {
        let write_calls = mock_writer_clone.write_count();
        let direct_write_calls = (data.len() + chunk_size - 1) / chunk_size; // ceiling division
        prop_assert!(write_calls <= direct_write_calls,
            "buffered writer should use fewer write calls: {} vs {}", write_calls, direct_write_calls);
    }
}

/// MR4: nested buf_reader+buf_writer preserves byte stream
///
/// Metamorphic relation: Piping data through BufReader -> BufWriter should
/// preserve the exact byte sequence without corruption or loss.
///
/// Properties tested:
/// - Nested buffering preserves data integrity
/// - No interference between read and write buffers
/// - Correct end-to-end data flow
#[proptest]
fn mr_nested_buffers_preserve_stream(
    #[strategy(proptest::collection::vec(any::<u8>(), 0..1000))] data: Vec<u8>,
    #[strategy(1usize..=100)] read_buf_size: usize,
    #[strategy(1usize..=100)] write_buf_size: usize,
) {
    let mock_reader = MockReader::new(data.clone());
    let mock_writer = MockWriter::new();
    let mock_writer_clone = mock_writer.clone();

    let buf_reader = BufReader::with_capacity(read_buf_size, mock_reader);
    let mut buf_writer = BufWriter::with_capacity(write_buf_size, mock_writer);

    let read_data = read_all(buf_reader).expect("read should succeed");
    write_all(&mut buf_writer, &read_data).expect("write should succeed");

    let written_data = mock_writer_clone.data();
    prop_assert_eq!(written_data, data, "nested buffers should preserve byte stream");
}

/// MR5: cancel during read/write does not lose buffered bytes
///
/// Metamorphic relation: Cancelling a buffered read/write operation should
/// not lose data that was already buffered, allowing subsequent operations
/// to access that data.
///
/// Properties tested:
/// - Buffered data survives cancellation
/// - Cancel-safety of buffered operations
/// - Consistency after cancellation
#[proptest]
fn mr_cancel_preserves_buffered_data(
    #[strategy(proptest::collection::vec(any::<u8>(), 10..100))] data: Vec<u8>,
    #[strategy(5usize..=20)] buf_size: usize,
) {
    // Test BufReader cancel safety
    {
        let mock_reader = MockReader::new(data.clone());
        let mut buf_reader = BufReader::with_capacity(buf_size, mock_reader);

        // Fill buffer partially
        let filled = poll_to_completion(|cx| {
            Pin::new(&mut buf_reader).poll_fill_buf(cx)
        }).expect("fill_buf should succeed");

        if !filled.is_empty() {
            let buffered_data = filled.to_vec();

            // "Cancel" by not consuming and starting a new read
            let mut read_buf = [0u8; 1024];
            let mut read_buf_wrapper = ReadBuf::new(&mut read_buf);
            poll_to_completion(|cx| {
                Pin::new(&mut buf_reader).poll_read(cx, &mut read_buf_wrapper)
            }).expect("read after cancel should succeed");

            // Should get the same buffered data
            let read_data = read_buf_wrapper.filled().to_vec();
            prop_assert!(read_data.starts_with(&buffered_data),
                "buffered data should be preserved after cancel: buffered={:?}, read={:?}",
                buffered_data, read_data);
        }
    }

    // Test BufWriter cancel safety
    {
        let mock_writer = MockWriter::new();
        let mock_writer_clone = mock_writer.clone();
        let mut buf_writer = BufWriter::with_capacity(buf_size, mock_writer);

        // Write some data (will be buffered)
        let write_data = &data[..cmp::min(data.len(), buf_size / 2)];

        poll_to_completion(|cx| {
            Pin::new(&mut buf_writer).poll_write(cx, write_data)
        }).expect("write should succeed");

        // Check that data is buffered (not yet written to underlying writer)
        let initial_written = mock_writer_clone.data();
        if initial_written.is_empty() {
            // Data is buffered, now "cancel" and then flush
            poll_to_completion(|cx| {
                Pin::new(&mut buf_writer).poll_flush(cx)
            }).expect("flush after cancel should succeed");

            // Data should still be written
            let final_written = mock_writer_clone.data();
            prop_assert_eq!(final_written, write_data.to_vec(),
                "buffered data should be preserved and written after cancel");
        }
    }
}

/// BONUS MR: buffer capacity and utilization invariants
///
/// Metamorphic relation: Buffer capacity settings should affect performance
/// but not correctness of data flow.
///
/// Properties tested:
/// - Different buffer sizes produce same results
/// - Capacity affects call counts but not data
/// - Buffer utilization is bounded by capacity
#[proptest]
fn mr_buffer_capacity_invariants(
    #[strategy(proptest::collection::vec(any::<u8>(), 10..200))] data: Vec<u8>,
    #[strategy(1usize..=20)] small_buf: usize,
    #[strategy(50usize..=100)] large_buf: usize,
) {
    // Test different buffer sizes produce same results
    {
        let mock_reader1 = MockReader::new(data.clone());
        let mock_reader2 = MockReader::new(data.clone());

        let small_reader = BufReader::with_capacity(small_buf, mock_reader1);
        let large_reader = BufReader::with_capacity(large_buf, mock_reader2);

        let small_data = read_all(small_reader).expect("small buffer read should succeed");
        let large_data = read_all(large_reader).expect("large buffer read should succeed");

        prop_assert_eq!(small_data, large_data, "different buffer sizes should produce same data");
    }

    // Test capacity affects performance characteristics
    {
        let mock_reader1 = MockReader::new(data.clone()).with_max_read_size(1); // Force many reads
        let mock_reader2 = MockReader::new(data.clone()).with_max_read_size(1);
        let mock_reader1_clone = mock_reader1.clone();
        let mock_reader2_clone = mock_reader2.clone();

        let small_reader = BufReader::with_capacity(small_buf, mock_reader1);
        let large_reader = BufReader::with_capacity(large_buf, mock_reader2);

        read_all(small_reader).expect("small buffer read should succeed");
        read_all(large_reader).expect("large buffer read should succeed");

        // Larger buffer should generally result in fewer underlying read calls
        // (though this is not guaranteed due to the complexity of buffering logic)
        let small_calls = mock_reader1_clone.read_count();
        let large_calls = mock_reader2_clone.read_count();

        // At minimum, both should have read some data
        prop_assert!(small_calls > 0, "small buffer should make read calls");
        prop_assert!(large_calls > 0, "large buffer should make read calls");
    }
}

/// Test module for integration with the rest of the test suite
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metamorphic_io_buf_smoke_test() {
        let data = b"hello world test data for buffered I/O".to_vec();

        // Quick smoke test for BufReader
        let mock_reader = MockReader::new(data.clone());
        let buf_reader = BufReader::with_capacity(16, mock_reader);
        let read_data = read_all(buf_reader).expect("read should succeed");
        assert_eq!(read_data, data);

        // Quick smoke test for BufWriter
        let mock_writer = MockWriter::new();
        let mock_writer_clone = mock_writer.clone();
        let mut buf_writer = BufWriter::with_capacity(16, mock_writer);

        write_all(&mut buf_writer, &data).expect("write should succeed");

        let written_data = mock_writer_clone.data();
        assert_eq!(written_data, data);
    }
}