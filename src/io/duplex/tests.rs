#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use std::sync::Weak;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

#[derive(Default)]
struct Count(AtomicUsize);

impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counter() -> (Arc<Count>, Waker) {
    let count = Arc::new(Count::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

fn read(
    stream: &mut DuplexStream,
    size: usize,
    waker: &Waker,
) -> (Poll<io::Result<()>>, Vec<u8>) {
    let mut bytes = vec![0; size];
    let mut buf = ReadBuf::new(&mut bytes);
    let result = Pin::new(stream).poll_read(&mut Context::from_waker(waker), &mut buf);
    (result, buf.filled().to_vec())
}

fn write(stream: &mut DuplexStream, bytes: &[u8], waker: &Waker) -> Poll<io::Result<usize>> {
    Pin::new(stream).poll_write(&mut Context::from_waker(waker), bytes)
}

#[test]
fn empty_reads_never_park_consume_bytes_or_wake_a_blocked_writer() {
    let (mut a, mut b) = duplex(1);
    let (count, waker) = counter();
    assert!(matches!(read(&mut a, 0, &waker).0, Poll::Ready(Ok(()))));
    assert!(a.read.lock().read_waker.is_none());
    assert!(matches!(write(&mut b, b"x", &waker), Poll::Ready(Ok(1))));
    assert!(write(&mut b, b"y", &waker).is_pending());
    assert!(matches!(read(&mut a, 0, &waker).0, Poll::Ready(Ok(()))));
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(read(&mut a, 1, Waker::noop()).1, b"x");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
}

#[test]
fn full_pipe_parks_and_a_partial_read_wakes_the_writer_once() {
    let (mut a, mut b) = duplex(3);
    let (count, waker) = counter();
    assert!(matches!(write(&mut a, b"abcd", &waker), Poll::Ready(Ok(3))));
    for _ in 0..4 {
        assert!(write(&mut a, b"d", &waker).is_pending());
    }
    assert_eq!(count.0.load(Ordering::SeqCst), 0, "no self-wake spin");
    assert_eq!(read(&mut b, 1, Waker::noop()).1, b"a");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(matches!(write(&mut a, b"de", &waker), Poll::Ready(Ok(1))));
    assert_eq!(read(&mut b, 8, Waker::noop()).1, b"bcd");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
}

#[test]
fn half_close_drains_buffer_before_eof_and_keeps_reverse_direction_open() {
    let (mut a, mut b) = duplex(4);
    assert!(matches!(write(&mut a, b"abcd", Waker::noop()), Poll::Ready(Ok(4))));
    assert!(matches!(
        Pin::new(&mut a).poll_shutdown(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(read(&mut b, 2, Waker::noop()).1, b"ab");
    assert_eq!(read(&mut b, 4, Waker::noop()).1, b"cd");
    let (eof, bytes) = read(&mut b, 4, Waker::noop());
    assert!(matches!(eof, Poll::Ready(Ok(()))));
    assert!(bytes.is_empty());
    assert!(matches!(write(&mut b, b"ok", Waker::noop()), Poll::Ready(Ok(2))));
    assert_eq!(read(&mut a, 4, Waker::noop()).1, b"ok");
    assert!(matches!(
        write(&mut a, b"no", Waker::noop()),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
}

struct ReenterOnDrop {
    pipe: Weak<Mutex<Pipe>>,
    peer: Arc<Mutex<DuplexStream>>,
    read_peer: bool,
    unlocked: Arc<Mutex<Vec<bool>>>,
}

#[allow(clippy::manual_noop_waker)]
impl Wake for ReenterOnDrop {
    fn wake(self: Arc<Self>) {}
}

impl Drop for ReenterOnDrop {
    fn drop(&mut self) {
        let unlocked = self.pipe.upgrade().is_some_and(|pipe| pipe.try_lock().is_some());
        self.unlocked.lock().push(unlocked);
        // The old implementation fails the witness instead of hanging this
        // test. The real peer operation runs only when the lock was released.
        if unlocked {
            let mut peer = self.peer.lock();
            if self.read_peer {
                assert_eq!(read(&mut peer, 1, Waker::noop()).1, b"x");
            } else {
                assert!(matches!(write(&mut peer, b"x", Waker::noop()), Poll::Ready(Ok(1))));
            }
        }
    }
}

#[test]
fn replacing_read_waker_can_reenter_peer_write_and_wake_the_new_reader() {
    let (mut a, b) = duplex(4);
    let peer = Arc::new(Mutex::new(b));
    let unlocked = Arc::new(Mutex::new(Vec::new()));
    let old = Waker::from(Arc::new(ReenterOnDrop {
        pipe: Arc::downgrade(&a.read),
        peer: Arc::clone(&peer),
        read_peer: false,
        unlocked: Arc::clone(&unlocked),
    }));
    assert!(read(&mut a, 1, &old).0.is_pending());
    drop(old);
    let (count, new) = counter();
    assert!(read(&mut a, 1, &new).0.is_pending());
    assert_eq!(*unlocked.lock(), vec![true]);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(read(&mut a, 1, &new).1, b"x");
}

#[test]
fn replacing_write_waker_can_reenter_peer_read_and_wake_the_new_writer() {
    let (mut a, b) = duplex(1);
    let peer = Arc::new(Mutex::new(b));
    assert!(matches!(write(&mut a, b"x", Waker::noop()), Poll::Ready(Ok(1))));
    let unlocked = Arc::new(Mutex::new(Vec::new()));
    let old = Waker::from(Arc::new(ReenterOnDrop {
        pipe: Arc::downgrade(&a.write),
        peer: Arc::clone(&peer),
        read_peer: true,
        unlocked: Arc::clone(&unlocked),
    }));
    assert!(write(&mut a, b"y", &old).is_pending());
    drop(old);
    let (count, new) = counter();
    assert!(write(&mut a, b"y", &new).is_pending());
    assert_eq!(*unlocked.lock(), vec![true]);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(matches!(write(&mut a, b"y", &new), Poll::Ready(Ok(1))));
    assert_eq!(read(&mut peer.lock(), 1, Waker::noop()).1, b"y");
}

#[test]
fn dropping_an_endpoint_retires_both_of_its_abandoned_wakers() {
    let (mut a, mut b) = duplex(1);
    let (read_count, reader) = counter();
    let (write_count, writer) = counter();
    let read_weak = Arc::downgrade(&read_count);
    let write_weak = Arc::downgrade(&write_count);
    assert!(read(&mut a, 1, &reader).0.is_pending());
    assert!(matches!(write(&mut a, b"x", &writer), Poll::Ready(Ok(1))));
    assert!(write(&mut a, b"y", &writer).is_pending());
    drop(reader);
    drop(writer);
    drop(read_count);
    drop(write_count);
    assert!(read_weak.upgrade().is_some());
    assert!(write_weak.upgrade().is_some());
    drop(a);
    assert!(read_weak.upgrade().is_none());
    assert!(write_weak.upgrade().is_none());
    assert_eq!(read(&mut b, 4, Waker::noop()).1, b"x", "committed bytes survive");
    assert!(matches!(
        write(&mut b, b"z", Waker::noop()),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
}

#[test]
fn shutdown_retires_an_abandoned_write_waiter_without_discarding_buffered_bytes() {
    let (mut a, mut b) = duplex(1);
    let (count, waker) = counter();
    let weak = Arc::downgrade(&count);
    assert!(matches!(write(&mut a, b"x", &waker), Poll::Ready(Ok(1))));
    assert!(write(&mut a, b"y", &waker).is_pending());
    drop(count);
    drop(waker);
    assert!(weak.upgrade().is_some());
    for _ in 0..2 {
        assert!(matches!(
            Pin::new(&mut a).poll_shutdown(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
    assert!(weak.upgrade().is_none());
    assert_eq!(read(&mut b, 1, Waker::noop()).1, b"x");
}

struct Panics;

impl Wake for Panics {
    fn wake(self: Arc<Self>) {
        panic!("duplex wake sentinel");
    }
}

#[test]
fn a_panicking_reader_wake_cannot_skip_peer_write_closure_and_notification() {
    for already_unwinding in [false, true] {
        let (mut a, b) = duplex(1);
        assert!(read(&mut a, 1, &Waker::from(Arc::new(Panics))).0.is_pending());
        assert!(matches!(write(&mut a, b"x", Waker::noop()), Poll::Ready(Ok(1))));
        let (count, writer) = counter();
        assert!(write(&mut a, b"y", &writer).is_pending());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let peer = b;
            if already_unwinding {
                let _peer = peer;
                panic!("outer unwind sentinel");
            }
            drop(peer);
        }));
        let payload = result.expect_err("preserve the original panic");
        assert_eq!(
            payload.downcast_ref::<&str>().copied(),
            Some(if already_unwinding { "outer unwind sentinel" } else { "duplex wake sentinel" })
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1, "other direction still notified");
        assert!(matches!(
            write(&mut a, b"z", Waker::noop()),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
        let (eof, bytes) = read(&mut a, 1, Waker::noop());
        assert!(matches!(eof, Poll::Ready(Ok(()))));
        assert!(bytes.is_empty());
    }
}

#[test]
fn native_runtime_protocol_exchange_completes_with_one_byte_backpressure() {
    use crate::io::{AsyncReadExt, AsyncWriteExt};
    use crate::runtime::RuntimeBuilder;

    crate::test_utils::init_test_logging();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let (mut client, mut server) = duplex(1);
        let client_side = async {
            client.write_all(b"request").await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
        };
        let server_side = async {
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            server.write_all(b"response").await.unwrap();
            server.shutdown().await.unwrap();
        };
        futures_lite::future::zip(client_side, server_side).await;
    });
}
