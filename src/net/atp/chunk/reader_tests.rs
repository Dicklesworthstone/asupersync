use super::*;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

struct Fragmented {
    bytes: Vec<u8>,
    position: usize,
    max_read: usize,
    pending: bool,
    alternate_pending: bool,
    polls: usize,
}

impl Fragmented {
    fn new(bytes: Vec<u8>, max_read: usize) -> Self {
        Self { bytes, position: 0, max_read, pending: false, alternate_pending: true, polls: 0 }
    }
}

impl AsyncRead for Fragmented {
    fn poll_read(mut self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>>
    {
        self.polls += 1;
        if self.pending {
            self.pending = false;
            task.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = buf.remaining().min(self.max_read).min(self.bytes.len() - self.position);
        buf.put_slice(&self.bytes[self.position..self.position + n]);
        self.position += n;
        self.pending = self.alternate_pending && n > 0;
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Ready,
    Pending,
    Error,
    Panic,
    Replace,
}

struct Script {
    steps: VecDeque<(&'static [u8], Reply)>,
    polls: usize,
}

impl Script {
    fn new(steps: impl IntoIterator<Item = (&'static [u8], Reply)>) -> Self {
        Self { steps: steps.into_iter().collect(), polls: 0 }
    }
}

impl AsyncRead for Script {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>>
    {
        self.polls += 1;
        let (bytes, reply) = self.steps.pop_front().unwrap_or((b"", Reply::Ready));
        if matches!(reply, Reply::Replace) {
            // An arbitrary provider can replace ReadBuf with unrelated storage
            // using safe Rust. No unsafe code is needed to witness this defect.
            let foreign = Box::leak(vec![99u8].into_boxed_slice());
            *buf = ReadBuf::new(foreign);
            buf.advance(1);
            return Poll::Ready(Ok(()));
        }
        buf.put_slice(bytes);
        match reply {
            Reply::Ready => Poll::Ready(Ok(())),
            Reply::Pending => Poll::Pending,
            Reply::Error => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "source error"))),
            Reply::Panic => panic!("source panic after writing bytes"),
            Reply::Replace => unreachable!(),
        }
    }
}

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn wake_counter() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    (count, waker)
}

#[test]
fn construction_is_bounded_and_does_not_read_or_allocate_payloads() {
    for size in [0, 1_048_577, usize::MAX] {
        let error = StreamChunkReader::new(Script::new([]), size).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    for size in [1, 65_536, 1_048_576] {
        let reader = StreamProfile::chunk_reader(Script::new([]), size).unwrap();
        assert_eq!(reader.get_ref().polls, 0);
        assert_eq!(reader.buffer.capacity(), 0);
        assert!(reader.buffered_bytes().is_empty());
    }
}

#[test]
fn arbitrary_fragmentation_preserves_payloads_descriptors_and_hashes() {
    futures_lite::future::block_on(async {
        for length in [0, 1, 3, 4, 7, 8, 9, 16, 17, 255] {
            let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            for chunk_size in [1, 2, 7, 16, 64] {
                for max_read in [1, 3, 23] {
                    let mut reader = StreamChunkReader::new(
                        Fragmented::new(bytes.clone(), max_read), chunk_size,
                    ).unwrap();
                    let mut offset = 0;
                    let mut index = 0;
                    while let Some(chunk) = reader.next_chunk().await.unwrap() {
                        let end = (offset + chunk_size).min(length);
                        assert_eq!(chunk.bytes, bytes[offset..end]);
                        assert_eq!(chunk.boundary.index, index);
                        assert_eq!(chunk.boundary.byte_offset, offset as u64);
                        assert_eq!(chunk.boundary.size_bytes, (end - offset) as u64);
                        let expected_hash: [u8; 32] = Sha256::digest(&bytes[offset..end]).into();
                        assert_eq!(chunk.boundary.content_hash, expected_hash);
                        assert_eq!(reader.get_ref().position, end, "no read-ahead past emitted chunk");
                        assert_eq!(reader.emitted_bytes(), end as u64);
                        assert!(reader.buffered_bytes().is_empty());
                        offset = end;
                        index += 1;
                    }
                    assert_eq!(offset, length);
                    assert!(reader.is_eof());
                    let polls = reader.get_ref().polls;
                    assert!(reader.next_chunk().await.unwrap().is_none());
                    assert_eq!(reader.get_ref().polls, polls, "EOF is fused");
                }
            }
        }
    });
}

#[test]
fn a_complete_chunk_is_returned_before_eof_without_speculative_reads() {
    let mut reader = StreamChunkReader::new(
        Script::new([(b"abcd".as_slice(), Reply::Ready), (b"", Reply::Pending)]), 4,
    ).unwrap();
    let chunk = futures_lite::future::block_on(reader.next_chunk()).unwrap().unwrap();
    assert_eq!(chunk.bytes, b"abcd");
    assert_eq!(reader.get_ref().polls, 1);
    assert!(!reader.is_eof());
    assert_eq!(reader.buffer.capacity(), 0, "no next-chunk allocation until requested");
}

#[test]
fn dropped_borrowing_wait_keeps_its_partial_chunk() {
    let mut reader = StreamChunkReader::new(Script::new([
        (b"ab".as_slice(), Reply::Ready), (b"", Reply::Pending), (b"cd", Reply::Ready),
    ]), 4).unwrap();
    let mut wait = Box::pin(reader.next_chunk());
    assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(wait);
    assert_eq!(reader.buffered_bytes(), b"ab");
    assert_eq!(reader.emitted_bytes(), 0);
    let chunk = futures_lite::future::block_on(reader.next_chunk()).unwrap().unwrap();
    assert_eq!(chunk.bytes, b"abcd");
    assert_eq!(chunk.boundary.index, 0);
    assert_eq!(chunk.boundary.byte_offset, 0);
}

#[test]
fn original_errors_with_progress_preserve_partial_and_full_chunks_for_retry() {
    for error_bytes in [b"c".as_slice(), b"cd".as_slice()] {
        let mut steps = vec![(b"ab".as_slice(), Reply::Ready), (error_bytes, Reply::Error)];
        if error_bytes.len() == 1 { steps.push((b"d", Reply::Ready)); }
        let mut reader = StreamChunkReader::new(Script::new(steps), 4).unwrap();
        let error = futures_lite::future::block_on(reader.next_chunk()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "source error");
        assert_eq!(reader.buffered_bytes(), &b"abcd"[..2 + error_bytes.len()]);
        let chunk = futures_lite::future::block_on(reader.next_chunk()).unwrap().unwrap();
        assert_eq!(chunk.bytes, b"abcd");
        assert_eq!(reader.get_ref().polls, if error_bytes.len() == 1 { 3 } else { 2 });
    }
}

#[test]
fn positive_pending_progress_is_retained_and_woken_but_empty_pending_is_not() {
    let mut reader = StreamChunkReader::new(Script::new([
        (b"ab".as_slice(), Reply::Pending), (b"", Reply::Pending), (b"cd", Reply::Pending),
    ]), 4).unwrap();
    let (count, waker) = wake_counter();
    let mut task = Context::from_waker(&waker);
    assert!(reader.poll_next_chunk(&mut task).is_pending());
    assert_eq!(reader.buffered_bytes(), b"ab");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(reader.poll_next_chunk(&mut task).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    let Poll::Ready(Ok(Some(chunk))) = reader.poll_next_chunk(&mut task) else {
        panic!("positive Pending must not hide a complete chunk");
    };
    assert_eq!(chunk.bytes, b"abcd");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
}

#[test]
fn ready_short_reads_yield_after_the_per_poll_budget() {
    let mut source = Fragmented::new(vec![7; 40], 1);
    source.alternate_pending = false;
    let mut reader = StreamChunkReader::new(source, 32).unwrap();
    let (count, waker) = wake_counter();
    assert!(reader.poll_next_chunk(&mut Context::from_waker(&waker)).is_pending());
    assert_eq!(reader.get_ref().polls, READS_PER_POLL);
    assert_eq!(reader.buffered_bytes(), vec![7; READS_PER_POLL]);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    let first = futures_lite::future::block_on(reader.next_chunk()).unwrap().unwrap();
    assert_eq!(first.bytes, vec![7; 32]);
    assert_eq!(reader.get_ref().position, 32);
    let tail = futures_lite::future::block_on(reader.next_chunk()).unwrap().unwrap();
    assert_eq!(tail.bytes, vec![7; 8]);
    assert!(reader.is_eof());
}

#[test]
fn provider_storage_replacement_is_a_sticky_refusal() {
    let mut reader = StreamChunkReader::new(Script::new([
        (b"ab".as_slice(), Reply::Ready), (b"", Reply::Replace),
    ]), 4).unwrap();
    let error = futures_lite::future::block_on(reader.next_chunk()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(reader.buffered_bytes(), b"ab");
    let polls = reader.get_ref().polls;
    assert!(futures_lite::future::block_on(reader.next_chunk()).is_err());
    assert_eq!(reader.get_ref().polls, polls);
}

#[test]
fn provider_panic_propagates_without_allowing_unknown_progress_to_be_replayed() {
    let mut reader = StreamChunkReader::new(Script::new([
        (b"ab".as_slice(), Reply::Ready), (b"c", Reply::Panic),
    ]), 4).unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        futures_lite::future::block_on(reader.next_chunk())
    }));
    assert!(panic.is_err());
    assert_eq!(reader.buffered_bytes(), b"ab");
    let polls = reader.get_ref().polls;
    assert!(futures_lite::future::block_on(reader.next_chunk()).is_err());
    assert_eq!(reader.get_ref().polls, polls);
    let (_, prefix) = reader.into_parts();
    assert_eq!(prefix, b"ab");
}

#[test]
fn counters_do_not_wrap_and_last_representable_index_can_reach_eof() {
    let mut reader = StreamChunkReader::new(Fragmented::new(b"a".to_vec(), 1), 1).unwrap();
    reader.next_index = u64::from(u32::MAX);
    let last = futures_lite::future::block_on(reader.next_chunk()).unwrap().unwrap();
    assert_eq!(last.boundary.index, u32::MAX);
    assert!(futures_lite::future::block_on(reader.next_chunk()).unwrap().is_none());

    let mut reader = StreamChunkReader::new(Fragmented::new(b"ab".to_vec(), 1), 1).unwrap();
    reader.next_index = u64::from(u32::MAX);
    assert!(futures_lite::future::block_on(reader.next_chunk()).unwrap().is_some());
    assert!(futures_lite::future::block_on(reader.next_chunk()).unwrap_err().to_string().contains("index overflow"));

    let mut reader = StreamChunkReader::new(Fragmented::new(b"abc".to_vec(), 3), 4).unwrap();
    reader.offset = u64::MAX - 2;
    assert!(futures_lite::future::block_on(reader.next_chunk()).unwrap_err().to_string().contains("offset overflow"));
    assert_eq!(reader.emitted_bytes(), u64::MAX - 2);
}

#[test]
fn a_pinned_non_unpin_source_is_supported_by_the_stream_adapter() {
    use std::cell::Cell;
    use std::marker::PhantomPinned;
    use crate::stream::StreamExt;

    struct PinnedSource { done: Cell<bool>, address: Cell<usize>, _pin: PhantomPinned }
    impl AsyncRead for PinnedSource {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>)
            -> Poll<io::Result<()>>
        {
            let this = self.as_ref().get_ref();
            let address = std::ptr::from_ref(this).addr();
            if this.address.get() != 0 { assert_eq!(this.address.get(), address); }
            this.address.set(address);
            if !this.done.replace(true) { buf.put_slice(b"abc"); }
            Poll::Ready(Ok(()))
        }
    }
    let source = PinnedSource { done: Cell::new(false), address: Cell::new(0), _pin: PhantomPinned };
    let stream = StreamChunkReader::new(source, 3).unwrap();
    let chunks = futures_lite::future::block_on(stream.collect::<Vec<_>>());
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].as_ref().unwrap().bytes, b"abc");
}

#[test]
fn rolling_updates_are_deterministic_provisional_descriptors_not_verification() {
    let mut reader = StreamChunkReader::new(Fragmented::new(b"abc".to_vec(), 3), 3).unwrap();
    let chunk = futures_lite::future::block_on(reader.next_chunk()).unwrap().unwrap();
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    assert_eq!(chunk.boundary.content_hash, expected);
    let update = chunk.rolling_update(42);
    assert_eq!(update, chunk.rolling_update(42));
    assert_eq!(update.timestamp_nanos, 42);
    assert_eq!(update.chunk_hash, expected);
    assert_eq!(update.chunk_size, 3);
    assert_eq!(update.sequence, 0);
    assert!(!update.early_consumption_safe);
    assert_eq!(update.completion_ratio, 0.0);
}

#[test]
fn real_async_file_payload_is_chunked_without_whole_file_materialization() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source");
    let expected: Vec<u8> = (0..200_003).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &expected).unwrap();
    futures_lite::future::block_on(async {
        let file = crate::fs::File::open(&path).await.unwrap();
        let mut reader = StreamProfile::chunk_reader(file, 8191).unwrap();
        let mut total = 0;
        let mut hash = Sha256::new();
        while let Some(chunk) = reader.next_chunk().await.unwrap() {
            assert_eq!(chunk.boundary.byte_offset, total as u64);
            assert!(chunk.bytes.len() <= 8191);
            assert_eq!(chunk.bytes, expected[total..total + chunk.bytes.len()]);
            total += chunk.bytes.len();
            hash.update(&chunk.bytes);
        }
        assert_eq!(total, expected.len());
        assert_eq!(hash.finalize(), Sha256::digest(&expected));
    });
}
