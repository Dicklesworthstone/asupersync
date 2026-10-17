use super::*;
use crate::io::{AsyncRead, ReadBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;

struct Source {
    bytes: &'static [u8],
    pos: usize,
    width: usize,
    pause_at: usize,
    open: Arc<AtomicBool>,
    polls: Arc<AtomicUsize>,
    waiter: Option<Waker>,
    error_at: Option<usize>,
}

impl Source {
    fn new(bytes: &'static [u8], width: usize) -> Self {
        Self {
            bytes,
            pos: 0,
            width,
            pause_at: usize::MAX,
            open: Arc::new(AtomicBool::new(false)),
            polls: Arc::new(AtomicUsize::new(0)),
            waiter: None,
            error_at: None,
        }
    }
}

impl AsyncRead for Source {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        panic!("buffered helpers must not bypass poll_fill_buf");
    }
}

impl AsyncBufRead for Source {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        if this.error_at == Some(this.pos) {
            this.error_at = None;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "original buffered source error",
            )));
        }
        if this.pos >= this.pause_at && !this.open.load(Ordering::SeqCst) {
            this.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let end = this.bytes.len().min(this.pos.saturating_add(this.width));
        Poll::Ready(Ok(&this.bytes[this.pos..end]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        assert!(amt <= this.width.min(this.bytes.len() - this.pos));
        this.pos += amt;
    }
}

fn finish<F: Future + Unpin>(mut operation: F) -> F::Output {
    for _ in 0..4096 {
        if let Poll::Ready(result) = Pin::new(&mut operation)
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return result;
        }
    }
    panic!("finite source did not finish");
}

fn next<R: AsyncBufRead + Unpin>(split: &mut Split<R>) -> Option<io::Result<Vec<u8>>> {
    for _ in 0..4096 {
        if let Poll::Ready(result) = Pin::new(&mut *split)
            .poll_next(&mut Context::from_waker(Waker::noop()))
        {
            return result;
        }
    }
    panic!("finite segment did not finish");
}

#[test]
fn read_limit_includes_existing_prefix_and_delimiter() {
    let mut source = Source::new(b"abc\nNEXT", 2);
    let mut out = b"P".to_vec();
    assert_eq!(finish(source.read_until_limited(b'\n', &mut out, 5)).unwrap(), 4);
    assert_eq!(out, b"Pabc\n");
    assert_eq!(&source.bytes[source.pos..], b"NEXT");
}

#[test]
fn read_size_error_retains_prefix_and_first_unaccepted_byte() {
    let mut source = Source::new(b"abc\nNEXT", 64);
    let mut out = Vec::new();
    let error = finish(source.read_until_limited(b'\n', &mut out, 3)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(out, b"abc");
    assert_eq!(&source.bytes[source.pos..], b"\nNEXT");
    // Deliberate allowance increase continues the SAME frame, without replay.
    assert_eq!(finish(source.read_until_limited(b'\n', &mut out, 4)).unwrap(), 1);
    assert_eq!(out, b"abc\n");
    assert_eq!(&source.bytes[source.pos..], b"NEXT");
}

#[test]
fn invalid_initial_length_refuses_before_source_poll() {
    let mut source = Source::new(b"must not read", 1);
    let polls = Arc::clone(&source.polls);
    let mut out = b"existing".to_vec();
    let error = finish(source.read_until_limited(0, &mut out, 3)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(out, b"existing");
}

#[test]
fn exactly_full_read_accepts_eof_but_never_an_extra_delimiter() {
    for width in 1..=4 {
        let mut source = Source::new(b"abc", width);
        let mut out = Vec::new();
        assert_eq!(finish(source.read_until_limited(b'\n', &mut out, 3)).unwrap(), 3);
        assert_eq!(out, b"abc");
        assert_eq!(finish(source.read_until_limited(b'\n', &mut out, 3)).unwrap(), 0);
    }
}

#[test]
fn zero_read_limit_accepts_only_eof_without_consumption() {
    let mut empty = Source::new(b"", 1);
    let mut out = Vec::new();
    assert_eq!(finish(empty.read_until_limited(b'\n', &mut out, 0)).unwrap(), 0);
    let mut source = Source::new(b"\n", 1);
    assert_eq!(
        finish(source.read_until_limited(b'\n', &mut out, 0)).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
    );
    assert!(out.is_empty());
    assert_eq!(source.pos, 0);
}

#[test]
fn dropped_read_wait_does_not_reset_the_absolute_allowance() {
    let mut source = Source::new(b"abcdef\n", 2);
    source.pause_at = 2;
    let mut out = Vec::new();
    {
        let mut operation = source.read_until_limited(b'\n', &mut out, 4);
        assert!(Pin::new(&mut operation)
            .poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    assert_eq!(out, b"ab");
    assert_eq!(source.pos, 2);
    assert!(source.waiter.is_some());
    source.open.store(true, Ordering::SeqCst);
    source.waiter.take().unwrap().wake();
    assert_eq!(
        finish(source.read_until_limited(b'\n', &mut out, 4)).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
    );
    assert_eq!(out, b"abcd");
    assert_eq!(&source.bytes[source.pos..], b"ef\n");
}

#[test]
fn read_source_error_preserves_exact_error_and_committed_bytes() {
    let mut source = Source::new(b"abcd\nNEXT", 2);
    source.error_at = Some(2);
    let mut out = Vec::new();
    let error = finish(source.read_until_limited(b'\n', &mut out, 5)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(error.to_string(), "original buffered source error");
    assert_eq!(out, b"ab");
    assert_eq!(finish(source.read_until_limited(b'\n', &mut out, 5)).unwrap(), 3);
    assert_eq!(out, b"abcd\n");
}

#[test]
fn split_excludes_delimiter_and_accepts_exact_limit_at_eof() {
    for width in 1..=8 {
        let mut split = Source::new(b"abc|def", width).split_limited(b'|', 3);
        assert_eq!(next(&mut split).unwrap().unwrap(), b"abc");
        assert_eq!(next(&mut split).unwrap().unwrap(), b"def");
        assert!(next(&mut split).is_none());
    }
}

#[test]
fn oversized_split_fuses_once_and_recovers_all_partial_bytes() {
    let mut split = Source::new(b"ok|abcdef|NEXT", 64).split_limited(b'|', 3);
    assert_eq!(next(&mut split).unwrap().unwrap(), b"ok");
    assert_eq!(next(&mut split).unwrap().unwrap_err().kind(), io::ErrorKind::InvalidData);
    let before = split.reader.polls.load(Ordering::SeqCst);
    assert!(next(&mut split).is_none());
    assert!(next(&mut split).is_none());
    assert_eq!(split.reader.polls.load(Ordering::SeqCst), before);
    let (reader, partial) = split.into_parts();
    assert_eq!(partial, b"abc");
    assert_eq!(&reader.bytes[reader.pos..], b"def|NEXT");
}

#[test]
fn zero_split_limit_emits_empty_segments_but_rejects_payload() {
    let mut split = Source::new(b"||x|", 1).split_limited(b'|', 0);
    assert!(next(&mut split).unwrap().unwrap().is_empty());
    assert!(next(&mut split).unwrap().unwrap().is_empty());
    assert_eq!(next(&mut split).unwrap().unwrap_err().kind(), io::ErrorKind::InvalidData);
    let (reader, partial) = split.into_parts();
    assert!(partial.is_empty());
    assert_eq!(&reader.bytes[reader.pos..], b"x|");
    let mut trailing = Source::new(b"||", 2).split_limited(b'|', 0);
    assert!(next(&mut trailing).unwrap().unwrap().is_empty());
    assert!(next(&mut trailing).unwrap().unwrap().is_empty());
    assert!(next(&mut trailing).is_none());
}

#[test]
fn split_pending_and_source_error_do_not_erase_or_reset_partial_segment() {
    let mut source = Source::new(b"abcd|NEXT", 2);
    source.pause_at = 2;
    source.error_at = Some(2);
    let mut split = source.split_limited(b'|', 4);
    assert_eq!(next(&mut split).unwrap().unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(split.segment, b"ab");
    assert!(Pin::new(&mut split)
        .poll_next(&mut Context::from_waker(Waker::noop())).is_pending());
    assert_eq!(split.segment, b"ab");
    split.reader.open.store(true, Ordering::SeqCst);
    split.reader.waiter.take().unwrap().wake();
    assert_eq!(next(&mut split).unwrap().unwrap(), b"abcd");
    let (reader, partial) = split.into_parts();
    assert!(partial.is_empty());
    assert_eq!(&reader.bytes[reader.pos..], b"NEXT");
}

#[test]
fn into_parts_recovers_a_pending_unfinished_segment() {
    let mut source = Source::new(b"abcd|", 2);
    source.pause_at = 2;
    let mut split = source.split_limited(b'|', 4);
    assert!(Pin::new(&mut split)
        .poll_next(&mut Context::from_waker(Waker::noop())).is_pending());
    let (reader, partial) = split.into_parts();
    assert_eq!(partial, b"ab");
    assert_eq!(&reader.bytes[reader.pos..], b"cd|");
}

#[test]
fn binary_delimiters_and_usize_max_limits_do_not_overflow() {
    let mut source = Source::new(b"\xff\xfe\0tail", 1);
    let mut out = Vec::new();
    assert_eq!(finish(source.read_until_limited(0, &mut out, usize::MAX)).unwrap(), 3);
    assert_eq!(out, b"\xff\xfe\0");
    let mut split = Source::new(b"\xff\xfe\0tail", 2).split_limited(0, usize::MAX);
    assert_eq!(next(&mut split).unwrap().unwrap(), b"\xff\xfe");
    assert_eq!(next(&mut split).unwrap().unwrap(), b"tail");
    assert!(next(&mut split).is_none());
}

#[test]
fn every_small_buffer_width_and_limit_preserves_refused_continuation() {
    for width in 1..=10 {
        for limit in 0..=9 {
            let mut source = Source::new(b"abcdef|NEXT", width);
            let mut out = Vec::new();
            let result = finish(source.read_until_limited(b'|', &mut out, limit));
            if limit >= 7 {
                assert_eq!(result.unwrap(), 7);
                assert_eq!(out, b"abcdef|");
                assert_eq!(source.pos, 7);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert_eq!(out, &b"abcdef|"[..limit]);
                assert_eq!(source.pos, limit);
            }
            let mut split = Source::new(b"abcdef|NEXT", width).split_limited(b'|', limit);
            let first = next(&mut split).unwrap();
            if limit >= 6 {
                assert_eq!(first.unwrap(), b"abcdef");
                assert_eq!(split.reader.pos, 7);
            } else {
                assert_eq!(first.unwrap_err().kind(), io::ErrorKind::InvalidData);
                let (reader, prefix) = split.into_parts();
                assert_eq!(prefix, &b"abcdef"[..limit]);
                assert_eq!(reader.pos, limit);
            }
        }
    }
}

#[test]
fn unbounded_apis_keep_their_original_semantics() {
    let mut source = Source::new(b"abcdef|NEXT", 1);
    let mut out = Vec::new();
    assert_eq!(finish(source.read_until(b'|', &mut out)).unwrap(), 7);
    assert_eq!(out, b"abcdef|");
    let mut split = Source::new(b"|abcdef||tail|", 1).split(b'|');
    for expected in [b"".as_slice(), b"abcdef", b"", b"tail"] {
        assert_eq!(next(&mut split).unwrap().unwrap(), expected);
    }
    assert!(next(&mut split).is_none());
}

#[test]
fn limited_read_yields_after_bounded_ready_refills() {
    const BYTES: [u8; 128] = [b'a'; 128];
    struct WakeCount(AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake));
    let mut source = Source::new(&BYTES, 1);
    let mut out = Vec::new();
    {
        let mut operation = source.read_until_limited(0, &mut out, 100);
        assert!(Pin::new(&mut operation).poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(source.pos, 33);
    assert_eq!(out.len(), 33);
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        finish(source.read_until_limited(0, &mut out, 100)).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
    );
    assert_eq!(source.pos, 100);
    assert_eq!(out.len(), 100);
}

#[test]
fn limited_split_keeps_its_budget_across_cooperative_yields() {
    const BYTES: [u8; 128] = [b'a'; 128];
    let mut split = Source::new(&BYTES, 1).split_limited(0, 100);
    assert!(Pin::new(&mut split)
        .poll_next(&mut Context::from_waker(Waker::noop())).is_pending());
    assert_eq!(split.segment.len(), 33);
    assert_eq!(next(&mut split).unwrap().unwrap_err().kind(), io::ErrorKind::InvalidData);
    let (source, partial) = split.into_parts();
    assert_eq!(source.pos, 100);
    assert_eq!(partial.len(), 100);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_limited_read_refuses_before_peer_eof_and_retains_following_frame() {
    use crate::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};
    let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let (mut sender, receiver) = duplex(32);
        sender.write_all(b"oversized|NEXT").await.unwrap();
        // The sender remains open: rejection must not wait for connection EOF.
        let mut reader = BufReader::with_capacity(8, receiver);
        let mut record = Vec::new();
        assert_eq!(
            reader.read_until_limited(b'|', &mut record, 5).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
        );
        assert_eq!(record, b"overs");
        assert_eq!(reader.buffer(), b"ize");
        assert_eq!(reader.read_until_limited(b'|', &mut record, 10).await.unwrap(), 5);
        assert_eq!(record, b"oversized|");
        let mut following = [0; 4];
        reader.read_exact(&mut following).await.unwrap();
        assert_eq!(&following, b"NEXT");
        sender.shutdown().await.unwrap();
    });
}
