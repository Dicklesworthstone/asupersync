use super::*;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Weak};
use std::task::Wake;

// Cell deliberately makes this stream !Sync: the split must require only Send.
struct TestStream {
    input: Vec<u8>,
    offset: usize,
    output: Vec<u8>,
    polls: Cell<usize>,
    pending_read: bool,
    panic_read: bool,
    flushes: usize,
    shutdowns: usize,
    vector_reads: usize,
    vector_writes: usize,
    drops: Arc<AtomicUsize>,
}

impl TestStream {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            offset: 0,
            output: Vec::new(),
            polls: Cell::new(0),
            pending_read: false,
            panic_read: false,
            flushes: 0,
            shutdowns: 0,
            vector_reads: 0,
            vector_writes: 0,
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Drop for TestStream {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for TestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls.set(this.polls.get() + 1);
        assert!(!std::mem::take(&mut this.panic_read), "inner read panic sentinel");
        if this.pending_read {
            return Poll::Pending;
        }
        let count = buf.remaining().min(this.input.len() - this.offset);
        buf.put_slice(&this.input[this.offset..this.offset + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadVectored for TestStream {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.vector_reads += 1;
        let start = this.offset;
        for buf in bufs {
            let count = buf.len().min(this.input.len() - this.offset);
            buf[..count].copy_from_slice(&this.input[this.offset..this.offset + count]);
            this.offset += count;
        }
        Poll::Ready(Ok(this.offset - start))
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls.set(this.polls.get() + 1);
        this.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.vector_writes += 1;
        let start = this.output.len();
        for buf in bufs {
            this.output.extend_from_slice(buf);
        }
        Poll::Ready(Ok(this.output.len() - start))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting_waker() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&counter));
    (counter, waker)
}

#[test]
fn halves_are_send_and_sync_for_a_send_but_not_sync_stream() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OwnedReadHalf<TestStream>>();
    assert_send_sync::<OwnedWriteHalf<TestStream>>();
}

#[test]
fn read_write_vectored_and_shutdown_preserve_the_original_stream() {
    let (mut read, mut write) = split_owned(TestStream::new(b"abcdef"));
    assert!(read.is_pair_of(&write));
    assert!(write.is_pair_of(&read));
    assert!(write.is_write_vectored());
    let mut cx = Context::from_waker(Waker::noop());
    let mut first = [0; 2];
    let mut buf = ReadBuf::new(&mut first);
    assert!(matches!(
        Pin::new(&mut read).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buf.filled(), b"ab");
    let mut second = [0; 1];
    let mut third = [0; 3];
    let mut vectors = [IoSliceMut::new(&mut second), IoSliceMut::new(&mut third)];
    assert!(matches!(
        Pin::new(&mut read).poll_read_vectored(&mut cx, &mut vectors),
        Poll::Ready(Ok(4))
    ));
    assert_eq!(&second, b"c");
    assert_eq!(&third, b"def");
    assert!(matches!(
        Pin::new(&mut write).poll_write(&mut cx, b"x"),
        Poll::Ready(Ok(1))
    ));
    let vectors = [IoSlice::new(b"yz"), IoSlice::new(b"!")];
    assert!(matches!(
        Pin::new(&mut write).poll_write_vectored(&mut cx, &vectors),
        Poll::Ready(Ok(3))
    ));
    assert!(matches!(
        Pin::new(&mut write).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        Pin::new(&mut write).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
    let stream = write.reunite(read).unwrap();
    assert_eq!(stream.offset, 6);
    assert_eq!(stream.output, b"xyz!");
    assert_eq!((stream.flushes, stream.shutdowns), (1, 1));
    assert_eq!((stream.vector_reads, stream.vector_writes), (1, 1));
}

#[test]
fn contention_registers_the_latest_waker_without_performing_io() {
    let (read, mut write) = split_owned(TestStream::new(b"data"));
    let cx = Context::from_waker(Waker::noop());
    let Poll::Ready(guard) = read.shared.poll_acquire(Side::Read, &cx) else {
        panic!("uncontended acquisition must succeed");
    };
    let (first, first_waker) = counting_waker();
    let (latest, latest_waker) = counting_waker();
    assert!(
        Pin::new(&mut write).poll_write(&mut Context::from_waker(&first_waker), b"ignored")
            .is_pending()
    );
    assert!(
        Pin::new(&mut write).poll_write(&mut Context::from_waker(&latest_waker), b"also ignored")
            .is_pending()
    );
    assert_eq!(guard.stream.as_ref().unwrap().polls.get(), 0);
    drop(guard);
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(latest.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        Pin::new(&mut write).poll_write(&mut Context::from_waker(&latest_waker), b"committed"),
        Poll::Ready(Ok(9))
    ));
    assert_eq!(read.reunite(write).unwrap().output, b"committed");
}

#[test]
fn dropping_a_waiting_half_unregisters_it_and_keeps_its_peer_alive() {
    let stream = TestStream::new(b"data");
    let drops = Arc::clone(&stream.drops);
    let (mut read, write) = split_owned(stream);
    let cx = Context::from_waker(Waker::noop());
    let Poll::Ready(guard) = write.shared.poll_acquire(Side::Write, &cx) else {
        panic!("uncontended acquisition must succeed");
    };
    let (counter, waker) = counting_waker();
    let mut output = [0; 4];
    let mut buf = ReadBuf::new(&mut output);
    assert!(
        Pin::new(&mut read).poll_read(&mut Context::from_waker(&waker), &mut buf)
            .is_pending()
    );
    assert!(buf.filled().is_empty());
    drop(read);
    drop(guard);
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(write);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn mismatched_reunite_returns_both_owners_without_shutting_down() {
    let (read_a, write_a) = split_owned(TestStream::new(b"a"));
    let (read_b, write_b) = split_owned(TestStream::new(b"b"));
    assert!(!read_a.is_pair_of(&write_b));
    let OwnedReuniteError(read_a, write_b) = read_a.reunite(write_b).err().unwrap();
    let a = read_a.reunite(write_a).unwrap();
    let b = read_b.reunite(write_b).unwrap();
    assert_eq!(a.input, b"a");
    assert_eq!(b.input, b"b");
    assert_eq!((a.shutdowns, b.shutdowns), (0, 0));
}

#[test]
fn halves_can_move_to_different_threads_and_reunite() {
    let (mut read, mut write) = split_owned(TestStream::new(b"payload"));
    let start = Arc::new(Barrier::new(2));
    let reader_start = Arc::clone(&start);
    let reader = std::thread::spawn(move || {
        reader_start.wait();
        futures_lite::future::block_on(std::future::poll_fn(|cx| {
            let mut output = [0; 7];
            let mut buf = ReadBuf::new(&mut output);
            match Pin::new(&mut read).poll_read(cx, &mut buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    result.unwrap();
                    assert_eq!(buf.filled(), b"payload");
                    Poll::Ready(())
                }
            }
        }));
        read
    });
    let writer = std::thread::spawn(move || {
        start.wait();
        futures_lite::future::block_on(std::future::poll_fn(|cx| {
            Pin::new(&mut write).poll_write(cx, b"reply")
        }))
        .unwrap();
        write
    });
    let stream = reader
        .join()
        .unwrap()
        .reunite(writer.join().unwrap())
        .unwrap();
    assert_eq!(stream.output, b"reply");
    assert_eq!(stream.offset, 7);
}

struct LockCheckingWake {
    shared: Weak<Shared<TestStream>>,
    wakes: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Wake for LockCheckingWake {
    fn wake(self: Arc<Self>) {
        let shared = self.shared.upgrade().unwrap();
        assert!(shared.state.try_lock().is_ok(), "wake called under split lock");
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for LockCheckingWake {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            assert!(shared.state.try_lock().is_ok(), "waker dropped under split lock");
        }
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn replacing_and_waking_waiters_never_invokes_callbacks_under_the_lock() {
    let (read, mut write) = split_owned(TestStream::new(b""));
    let cx = Context::from_waker(Waker::noop());
    let Poll::Ready(guard) = read.shared.poll_acquire(Side::Read, &cx) else {
        panic!("uncontended acquisition must succeed");
    };
    let wakes = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
        let waker = Waker::from(Arc::new(LockCheckingWake {
            shared: Arc::downgrade(&read.shared),
            wakes: Arc::clone(&wakes),
            drops: Arc::clone(&drops),
        }));
        assert!(
            Pin::new(&mut write).poll_write(&mut Context::from_waker(&waker), b"x")
                .is_pending()
        );
    }
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(guard);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[test]
fn panic_restores_stream_ownership_and_wakes_the_contending_half() {
    let (read, mut write) = split_owned(TestStream::new(b""));
    let (counter, waker) = counting_waker();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let cx = Context::from_waker(Waker::noop());
        let Poll::Ready(_guard) = read.shared.poll_acquire(Side::Read, &cx) else {
            panic!("uncontended acquisition must succeed");
        };
        assert!(
            Pin::new(&mut write).poll_write(&mut Context::from_waker(&waker), b"not committed")
                .is_pending()
        );
        panic!("stream panic sentinel");
    }));
    assert!(failure.is_err());
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        Pin::new(&mut write).poll_write(&mut Context::from_waker(&waker), b"retry"),
        Poll::Ready(Ok(5))
    ));
    assert_eq!(read.reunite(write).unwrap().output, b"retry");
}

#[test]
fn pending_underlying_read_does_not_hold_the_write_gate() {
    let mut stream = TestStream::new(b"data");
    stream.pending_read = true;
    let (mut read, mut write) = split_owned(stream);
    let mut cx = Context::from_waker(Waker::noop());
    let mut output = [0; 4];
    let mut buf = ReadBuf::new(&mut output);
    assert!(Pin::new(&mut read).poll_read(&mut cx, &mut buf).is_pending());
    assert!(buf.filled().is_empty());
    assert!(matches!(
        Pin::new(&mut write).poll_write(&mut cx, b"request"),
        Poll::Ready(Ok(7))
    ));
    assert_eq!(read.reunite(write).unwrap().output, b"request");
}

#[test]
fn inner_poll_panic_releases_the_stream_for_the_other_half() {
    let mut stream = TestStream::new(b"data");
    stream.panic_read = true;
    let (mut read, mut write) = split_owned(stream);
    let mut cx = Context::from_waker(Waker::noop());
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut output = [0; 4];
        let mut buf = ReadBuf::new(&mut output);
        let _ = Pin::new(&mut read).poll_read(&mut cx, &mut buf);
    }));
    assert_eq!(
        failure.unwrap_err().downcast_ref::<&str>(),
        Some(&"inner read panic sentinel")
    );
    assert!(matches!(
        Pin::new(&mut write).poll_write(&mut cx, b"after panic"),
        Poll::Ready(Ok(11))
    ));
    assert_eq!(read.reunite(write).unwrap().output, b"after panic");
}
