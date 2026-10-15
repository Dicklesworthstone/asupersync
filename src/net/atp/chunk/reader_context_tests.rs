use super::*;
use crate::io::ReadBuf;
use crate::types::CancelKind;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

struct GatedSource {
    bytes: Vec<u8>,
    position: usize,
    pause_at: usize,
    released: Arc<AtomicBool>,
    polls: usize,
    require_io: bool,
}

impl GatedSource {
    fn new(pause_at: usize) -> Self {
        Self {
            bytes: b"abcd".to_vec(), position: 0, pause_at,
            released: Arc::new(AtomicBool::new(false)), polls: 0, require_io: false,
        }
    }
}

impl AsyncRead for GatedSource {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buffer: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>>
    {
        self.polls += 1;
        if self.require_io {
            crate::cx::io_gate::require_ambient_io("chunk-reader-test")?;
        }
        let end = if self.released.load(Ordering::SeqCst) {
            self.bytes.len()
        } else {
            self.pause_at.min(self.bytes.len())
        };
        if self.position == end && end < self.bytes.len() {
            return Poll::Pending;
        }
        let n = buffer.remaining().min(end - self.position);
        buffer.put_slice(&self.bytes[self.position..self.position + n]);
        self.position += n;
        Poll::Ready(Ok(()))
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
fn pre_cancelled_context_does_not_poll_or_allocate_a_source_chunk() {
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let mut reader = StreamChunkReader::new(GatedSource::new(4), 4).unwrap();
    let error = futures_lite::future::block_on(reader.next_chunk_with_cx(&cx)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(reader.get_ref().polls, 0);
    assert_eq!(reader.buffer.capacity(), 0);
    assert_eq!(reader.emitted_bytes(), 0);
}

#[test]
fn cancellation_wakes_a_parked_chunk_and_preserves_it_for_a_fresh_context() {
    let cx = Cx::for_testing();
    let mut reader = StreamChunkReader::new(GatedSource::new(2), 4).unwrap();
    let released = reader.get_ref().released.clone();
    let (count, waker) = wake_counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(reader.next_chunk_with_cx(&cx));
    assert!(wait.as_mut().poll(&mut task).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    drop(wait);
    assert_eq!(reader.get_ref().polls, 2, "cancelled wait does not repoll the source");
    assert_eq!(reader.buffered_bytes(), b"ab");
    released.store(true, Ordering::SeqCst);
    let fresh = Cx::for_testing();
    let chunk = futures_lite::future::block_on(reader.next_chunk_with_cx(&fresh)).unwrap().unwrap();
    assert_eq!(chunk.bytes, b"abcd");
    assert_eq!(chunk.boundary.index, 0);
    assert_eq!(chunk.boundary.byte_offset, 0);
}

#[test]
fn dropping_a_borrowing_wait_retires_only_its_cancellation_registration() {
    let cx = Cx::for_testing();
    let mut first = StreamChunkReader::new(GatedSource::new(0), 4).unwrap();
    let mut second = StreamChunkReader::new(GatedSource::new(0), 4).unwrap();
    let (first_count, first_waker) = wake_counter();
    let first_weak = Arc::downgrade(&first_count);
    let (second_count, second_waker) = wake_counter();
    let mut a = Box::pin(first.next_chunk_with_cx(&cx));
    let mut b = Box::pin(second.next_chunk_with_cx(&cx));
    assert!(a.as_mut().poll(&mut Context::from_waker(&first_waker)).is_pending());
    assert!(b.as_mut().poll(&mut Context::from_waker(&second_waker)).is_pending());
    drop(first_count);
    drop(first_waker);
    assert!(first_weak.upgrade().is_some());
    drop(a);
    assert!(first_weak.upgrade().is_none());
    cx.cancel_fast(CancelKind::User);
    assert!(second_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(b.as_mut().poll(&mut Context::from_waker(&second_waker)), Poll::Ready(Err(_))));
}

#[test]
fn supplied_context_controls_source_io_without_denying_pure_memory_work() {
    let denied = Cx::for_testing().restrict::<crate::cx::cap::None>();
    let mut source = GatedSource::new(4);
    source.require_io = true;
    let mut reader = StreamChunkReader::new(source, 4).unwrap();
    let error = futures_lite::future::block_on(reader.next_chunk_with_cx(&denied)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(reader.get_ref().position, 0);
    assert!(reader.buffered_bytes().is_empty());
    let allowed = Cx::for_testing();
    let chunk = futures_lite::future::block_on(reader.next_chunk_with_cx(&allowed)).unwrap().unwrap();
    assert_eq!(chunk.bytes, b"abcd");

    let mut memory = StreamChunkReader::new(GatedSource::new(4), 4).unwrap();
    assert!(futures_lite::future::block_on(memory.next_chunk_with_cx(&denied)).unwrap().is_some());
}

#[test]
fn masked_cancellation_does_not_abort_or_busy_wake_a_parked_reader() {
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let mut reader = StreamChunkReader::new(GatedSource::new(0), 4).unwrap();
    let (count, waker) = wake_counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(reader.next_chunk_with_cx(&cx));
    cx.masked(|| {
        for _ in 0..8 { assert!(wait.as_mut().poll(&mut task).is_pending()); }
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    });
    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    drop(wait);
    assert_eq!(reader.get_ref().polls, 8);
}

#[test]
fn masked_completed_chunk_can_be_delivered() {
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let mut reader = StreamChunkReader::new(GatedSource::new(4), 4).unwrap();
    let chunk = cx.masked(|| {
        futures_lite::future::block_on(reader.next_chunk_with_cx(&cx))
    }).unwrap().unwrap();
    assert_eq!(chunk.bytes, b"abcd");
    assert!(cx.checkpoint().is_err());
}

#[test]
fn completed_read_wins_a_cancellation_request_published_inside_its_poll() {
    struct CancelOnRead { cx: Cx, polls: usize }
    impl AsyncRead for CancelOnRead {
        fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buffer: &mut ReadBuf<'_>)
            -> Poll<io::Result<()>>
        {
            self.polls += 1;
            buffer.put_slice(b"ab");
            self.cx.cancel_fast(CancelKind::User);
            Poll::Ready(Ok(()))
        }
    }
    let cx = Cx::for_testing();
    let mut reader = StreamChunkReader::new(CancelOnRead { cx: cx.clone(), polls: 0 }, 2).unwrap();
    let chunk = futures_lite::future::block_on(reader.next_chunk_with_cx(&cx)).unwrap().unwrap();
    assert_eq!(chunk.bytes, b"ab", "committed output must not disappear into cancellation");
    assert_eq!(reader.emitted_bytes(), 2);
    assert!(futures_lite::future::block_on(reader.next_chunk_with_cx(&cx)).is_err());
    assert_eq!(reader.get_ref().polls, 1);
}

#[test]
fn native_duplex_transfer_resumes_after_a_witnessed_partial_chunk_wait_is_dropped() {
    use crate::io::{AsyncWriteExt, duplex};
    use crate::runtime::RuntimeBuilder;
    use sha2::{Digest, Sha256};

    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let expected: Vec<u8> = (0..257).map(|i| (i % 251) as u8).collect();
        let (mut writer, source) = duplex(2);
        let cx = Cx::for_testing();
        let mut chunks = StreamChunkReader::new(source, 17).unwrap();
        let mut writing = Box::pin(async {
            writer.write_all(&expected).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut task = Context::from_waker(Waker::noop());
        assert!(writing.as_mut().poll(&mut task).is_pending());
        let mut wait = Box::pin(chunks.next_chunk_with_cx(&cx));
        assert!(wait.as_mut().poll(&mut task).is_pending());
        drop(wait);
        assert_eq!(chunks.buffered_bytes(), &expected[..2], "real two-byte suspension witness");
        let reading = async {
            let mut received = Vec::new();
            while let Some(chunk) = chunks.next_chunk_with_cx(&cx).await.unwrap() {
                assert_eq!(chunk.boundary.byte_offset, received.len() as u64);
                let hash: [u8; 32] = Sha256::digest(&chunk.bytes).into();
                assert_eq!(chunk.boundary.content_hash, hash);
                received.extend_from_slice(&chunk.bytes);
            }
            assert_eq!(received, expected);
        };
        futures_lite::future::zip(writing, reading).await;
        assert!(chunks.is_eof());
        assert_eq!(chunks.emitted_bytes(), 257);
    });
}
