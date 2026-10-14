use super::*;
use crate::io::ext::AsyncBufReadExt;
use crate::io::{AsyncRead, ReadBuf};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;

#[derive(Default)]
struct Observations {
    polls: AtomicUsize,
    consumed: AtomicUsize,
    open: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

struct Source {
    bytes: &'static [u8],
    pos: usize,
    width: usize,
    paused_at: usize,
    error_at: Option<usize>,
    panic_peek: bool,
    panic_consume: bool,
    observed: Arc<Observations>,
}

impl Source {
    fn new(bytes: &'static [u8], width: usize) -> Self {
        Self {
            bytes, pos: 0, width, paused_at: usize::MAX, error_at: None,
            panic_peek: false, panic_consume: false,
            observed: Arc::new(Observations::default()),
        }
    }
}

impl AsyncRead for Source {
    fn poll_read(
        self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        panic!("discard must use the buffered source, not copy through a scratch buffer");
    }
}

impl AsyncBufRead for Source {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.observed.polls.fetch_add(1, Ordering::SeqCst);
        assert!(!this.panic_peek, "discard peek panic sentinel");
        if this.error_at == Some(this.pos) {
            this.error_at = None;
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "discard source error")));
        }
        if this.pos >= this.paused_at && !this.observed.open.load(Ordering::SeqCst) {
            *this.observed.waiter.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let end = this.bytes.len().min(this.pos.saturating_add(this.width));
        Poll::Ready(Ok(&this.bytes[this.pos..end]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        assert!(amt > 0, "discard must not call consume on EOF or zero admission");
        assert!(amt <= this.width.min(this.bytes.len() - this.pos));
        this.pos += amt;
        this.observed.consumed.fetch_add(amt, Ordering::SeqCst);
        assert!(!this.panic_consume, "discard consume panic sentinel");
    }
}

fn run<R: AsyncBufRead + Unpin + ?Sized>(session: &mut SkipUntilSession<'_, R>) -> io::Result<usize> {
    let mut wait = std::pin::pin!(session.run());
    for _ in 0..1024 {
        if let Poll::Ready(result) = wait.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            return result;
        }
    }
    panic!("finite discard did not finish");
}

fn poll_once<R: AsyncBufRead + Unpin + ?Sized>(
    session: &mut SkipUntilSession<'_, R>,
) -> Poll<io::Result<usize>> {
    let mut wait = std::pin::pin!(session.run());
    wait.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    // The borrowing wait is dropped here, but the session is retained.
}

#[test]
fn construction_and_unpolled_wait_never_consume_or_poll() {
    fn assert_send<T: Send>(_: T) {}
    let mut source = Source::new(b"abc|NEXT", 1);
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 4);
    assert_send(session.run()); // Dropping an unpolled wait is inert.
    assert_eq!(session.bytes_skipped(), 0);
    assert_eq!(session.remaining(), 4);
    assert_eq!(observed.polls.load(Ordering::SeqCst), 0);
    assert_eq!(observed.consumed.load(Ordering::SeqCst), 0);
    assert_eq!(session.into_inner().pos, 0);
}

#[test]
fn exact_delimiter_boundary_is_memoized_and_following_frame_is_untouched() {
    let mut source = Source::new(b"abc|NEXT", 64);
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 4);
    assert_eq!(run(&mut session).unwrap(), 4);
    assert!(session.delimiter_found());
    assert!(!session.is_eof());
    assert!(!session.limit_exceeded());
    assert_eq!(session.remaining(), 0);
    assert_eq!(run(&mut session).unwrap(), 4);
    assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
    let reader = session.into_inner();
    assert_eq!(&reader.bytes[reader.pos..], b"NEXT");
}

#[test]
fn eof_is_success_but_does_not_claim_a_delimiter_boundary() {
    let mut source = Source::new(b"abc", 1);
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 3);
    assert_eq!(run(&mut session).unwrap(), 3);
    assert!(session.is_eof());
    assert!(!session.delimiter_found());
    let polls = observed.polls.load(Ordering::SeqCst);
    assert_eq!(run(&mut session).unwrap(), 3);
    assert_eq!(observed.polls.load(Ordering::SeqCst), polls);
}

#[test]
fn size_refusal_neither_consumes_the_extra_delimiter_nor_repolls_the_provider() {
    let mut source = Source::new(b"abc|NEXT", 64);
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 3);
    assert_eq!(run(&mut session).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(session.bytes_skipped(), 3);
    assert_eq!(session.remaining(), 0);
    assert!(session.limit_exceeded());
    assert!(!session.is_poisoned());
    assert!(!session.delimiter_found());
    let polls = observed.polls.load(Ordering::SeqCst);
    for _ in 0..3 {
        assert_eq!(run(&mut session).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
    assert_eq!(observed.polls.load(Ordering::SeqCst), polls);
    assert_eq!(observed.consumed.load(Ordering::SeqCst), 3);
    let reader = session.into_inner();
    assert_eq!(&reader.bytes[reader.pos..], b"|NEXT");
    // A fresh allowance is an EXPLICIT recovery choice, not a reset on run().
    let mut remainder = reader.skip_until_limited(b'|', 1);
    assert_eq!(run(&mut remainder).unwrap(), 1);
    assert!(remainder.delimiter_found());
}

#[test]
fn zero_limit_can_observe_eof_or_pending_but_never_consume_a_byte() {
    for bytes in [b"".as_slice(), b"|", b"a"] {
        let mut source = Source::new(bytes, 1);
        let mut session = source.skip_until_limited(b'|', 0);
        let result = run(&mut session);
        if bytes.is_empty() {
            assert_eq!(result.unwrap(), 0);
            assert!(session.is_eof());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(session.limit_exceeded());
        }
        assert_eq!(session.into_inner().pos, 0);
    }
    let mut source = Source::new(b"", 1);
    source.paused_at = 0;
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 0);
    assert!(poll_once(&mut session).is_pending());
    assert!(!session.is_eof());
    observed.open.store(true, Ordering::SeqCst);
    observed.waiter.lock().unwrap().take().unwrap().wake();
    assert_eq!(run(&mut session).unwrap(), 0);
    assert!(session.is_eof());
}

#[test]
fn dropped_wait_retains_progress_and_cannot_reset_its_limit() {
    let mut source = Source::new(b"abcdef|NEXT", 2);
    source.paused_at = 2;
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 5);
    assert!(poll_once(&mut session).is_pending());
    assert_eq!(session.bytes_skipped(), 2);
    assert_eq!(session.remaining(), 3);
    assert_eq!(observed.consumed.load(Ordering::SeqCst), 2);
    assert!(!session.is_poisoned());
    observed.open.store(true, Ordering::SeqCst);
    observed.waiter.lock().unwrap().take().unwrap().wake();
    assert_eq!(run(&mut session).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(session.bytes_skipped(), 5);
    assert_eq!(observed.consumed.load(Ordering::SeqCst), 5);
    let source = session.into_inner();
    assert_eq!(&source.bytes[source.pos..], b"f|NEXT");
}

#[test]
fn interrupted_wait_returns_cumulative_success_on_resumption() {
    let mut source = Source::new(b"abcdef|NEXT", 2);
    source.paused_at = 2;
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 7);
    assert!(poll_once(&mut session).is_pending());
    assert_eq!(session.bytes_skipped(), 2);
    observed.open.store(true, Ordering::SeqCst);
    observed.waiter.lock().unwrap().take().unwrap().wake();
    assert_eq!(run(&mut session).unwrap(), 7); // Not just this run's five bytes.
    assert_eq!(session.bytes_skipped(), 7);
    assert!(session.delimiter_found());
}

#[test]
fn provider_errors_preserve_their_exact_error_and_do_not_refresh_the_budget() {
    let mut source = Source::new(b"abcde|NEXT", 2);
    source.error_at = Some(2);
    let mut session = source.skip_until_limited(b'|', 4);
    let error = run(&mut session).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(error.to_string(), "discard source error");
    assert_eq!(session.bytes_skipped(), 2);
    assert_eq!(session.remaining(), 2);
    assert!(!session.is_poisoned());
    assert_eq!(run(&mut session).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(session.bytes_skipped(), 4);
    let reader = session.into_inner();
    assert_eq!(&reader.bytes[reader.pos..], b"e|NEXT");
}

#[test]
fn panic_in_peek_or_consume_refuses_replay_and_preserves_the_original_panic() {
    for consume in [false, true] {
        let mut source = Source::new(b"abc|", 2);
        source.panic_peek = !consume;
        source.panic_consume = consume;
        let observed = Arc::clone(&source.observed);
        let mut session = source.skip_until_limited(b'|', 4);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run(&mut session);
        })).expect_err("provider panic must propagate");
        let text = panic.downcast_ref::<&str>().copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(text, Some(if consume { "discard consume panic sentinel" } else { "discard peek panic sentinel" }));
        assert!(session.is_poisoned());
        assert_eq!(session.bytes_skipped(), 0); // No successful consume receipt.
        assert_eq!(observed.consumed.load(Ordering::SeqCst), if consume { 2 } else { 0 });
        let polls = observed.polls.load(Ordering::SeqCst);
        assert_eq!(run(&mut session).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(observed.polls.load(Ordering::SeqCst), polls);
    }
}

#[test]
fn cooperative_work_budget_and_total_byte_budget_are_independent() {
    static BYTES: [u8; 4096] = [b'x'; 4096];
    struct WakeCount(AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake));
    let mut source = Source::new(&BYTES, 1);
    let observed = Arc::clone(&source.observed);
    let mut session = source.skip_until_limited(b'|', 1000);
    {
        let mut wait = std::pin::pin!(session.run());
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(observed.polls.load(Ordering::SeqCst), 32);
    assert_eq!(session.bytes_skipped(), 32);
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert_eq!(run(&mut session).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(session.bytes_skipped(), 1000);
    assert_eq!(observed.consumed.load(Ordering::SeqCst), 1000);
}

#[test]
fn byte_boundaries_match_flat_slice_oracle_for_every_small_limit_and_refill_width() {
    for (bytes, delimiter) in [
        (b"".as_slice(), b'|'), (b"|abc", b'|'), (b"abcdef|NEXT", b'|'),
        (b"abcdef", b'|'), (b"\xff\xfe\0rest", 0),
    ] {
        for width in 1..=12 {
            for limit in 0..=bytes.len() + 2 {
                let offered = limit.min(bytes.len());
                let boundary = bytes[..offered].iter().position(|&b| b == delimiter).map(|p| p + 1);
                let expected = boundary.unwrap_or(offered);
                let success = boundary.is_some() || offered == bytes.len();
                let mut source = Source::new(bytes, width);
                let mut session = source.skip_until_limited(delimiter, limit);
                let result = run(&mut session);
                assert_eq!(result.is_ok(), success, "width={width}, limit={limit}, bytes={bytes:?}");
                assert_eq!(session.bytes_skipped(), expected);
                assert_eq!(session.delimiter_found(), boundary.is_some());
                assert_eq!(session.is_eof(), success && boundary.is_none());
                assert_eq!(session.limit_exceeded(), !success);
                assert_eq!(session.into_inner().pos, expected);
            }
        }
    }
}

#[test]
fn public_session_accepts_trait_objects_and_maximum_counter_bounds() {
    let mut source = Source::new(b"\xff\xfe\0NEXT", 1);
    let reader: &mut (dyn AsyncBufRead + Unpin) = &mut source;
    let mut session = reader.skip_until_limited(0, usize::MAX);
    assert_eq!(run(&mut session).unwrap(), 3);
    assert_eq!(session.remaining(), usize::MAX - 3);
    assert!(session.delimiter_found());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_recovery_wait_can_be_dropped_then_resume_before_peer_eof() {
    use crate::io::{AsyncWriteExt, BufReader, duplex};
    let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let (mut sender, receiver) = duplex(64);
        sender.write_all(b"abcdef").await.unwrap();
        let mut reader = BufReader::with_capacity(16, receiver);
        let mut prefix = Vec::new();
        assert_eq!(reader.read_until_limited(b'|', &mut prefix, 3).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(prefix, b"abc");
        let mut discard = reader.skip_until_limited(b'|', 7);
        {
            let mut wait = std::pin::pin!(discard.run());
            let status = std::future::poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx))).await;
            assert!(status.is_pending());
        }
        assert_eq!(discard.bytes_skipped(), 3); // def consumed before parking.
        assert_eq!(discard.remaining(), 4);
        assert!(!discard.is_poisoned());
        sender.write_all(b"ghi|NEXT|").await.unwrap();
        assert_eq!(discard.run().await.unwrap(), 7);
        assert!(discard.delimiter_found());
        let reader = discard.into_inner();
        let mut next_record = Vec::new();
        assert_eq!(reader.read_until_limited(b'|', &mut next_record, 5).await.unwrap(), 5);
        assert_eq!(next_record, b"NEXT|");
        // Resynchronization completed while the peer was still open.
        sender.shutdown().await.unwrap();
    });
}

#[test]
fn oversized_split_can_explicitly_discard_the_remainder_before_parsing_again() {
    use crate::stream::Stream;
    let mut split = Source::new(b"abcdef|OK|", 2).split_limited(b'|', 3);
    let status = Pin::new(&mut split).poll_next(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(status, Poll::Ready(Some(Err(ref error))) if error.kind() == io::ErrorKind::InvalidData));
    let (mut reader, partial) = split.into_parts();
    assert_eq!(partial, b"abc");
    let mut discard = reader.skip_until_limited(b'|', 4);
    assert_eq!(run(&mut discard).unwrap(), 4);
    assert!(discard.delimiter_found());
    let mut record = Vec::new();
    let mut next_record = discard.into_inner().read_until_limited(b'|', &mut record, 3);
    let status = Pin::new(&mut next_record).poll(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(status, Poll::Ready(Ok(3))));
    assert_eq!(record, b"OK|");
}
