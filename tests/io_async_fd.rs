//! `asupersync::io::unix::AsyncFd`: reactor readiness waits for descriptors
//! the runtime does not wrap. Each test drives a non-blocking std socket pair
//! (a stand-in for an eventfd, pipe or C library socket) through `AsyncFd`
//! and has a plain thread make it ready, so a wait that returned before the
//! readiness, or never woke, fails the test.
#![cfg(unix)]

use asupersync::io::unix::AsyncFd;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::Interest;
use futures_lite::future::zip;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime")
        .block_on(fut)
}

fn nonblocking_pair() -> (UnixStream, UnixStream) {
    let (local, peer) = UnixStream::pair().expect("socket pair");
    local.set_nonblocking(true).expect("non-blocking");
    (local, peer)
}

/// Writes `bytes` to `peer` after `delay`, from a plain thread.
fn write_later(
    mut peer: UnixStream,
    delay: Duration,
    bytes: &'static [u8],
) -> thread::JoinHandle<UnixStream> {
    thread::spawn(move || {
        thread::sleep(delay);
        peer.write_all(bytes).expect("peer write");
        peer
    })
}

#[test]
fn async_io_waits_for_data_written_later() {
    let (local, peer) = nonblocking_pair();
    let fd = AsyncFd::new(local).expect("wrap");
    let writer = write_later(peer, Duration::from_millis(100), b"hello");
    let started = Instant::now();
    let (n, buf) = block_on(async {
        let mut buf = [0_u8; 16];
        let n = fd
            .async_io(Interest::READABLE, |stream| (&*stream).read(&mut buf))
            .await
            .expect("read");
        (n, buf)
    });
    assert_eq!(&buf[..n], b"hello");
    assert!(
        started.elapsed() >= Duration::from_millis(90),
        "the read waited for the write: {:?}",
        started.elapsed()
    );
    drop(writer.join().expect("writer"));
}

#[test]
fn would_block_clears_readiness_and_the_next_wait_parks_until_data() {
    let (local, peer) = nonblocking_pair();
    let fd = AsyncFd::new(local).expect("wrap");
    // Writable at once (an empty socket buffer); readable only after the
    // peer writes. The guard from `ready` says which direction it saw.
    let writer = write_later(peer, Duration::from_millis(300), b"x");
    block_on(async {
        assert!(fd.writable().await.expect("writable").is_writable());

        // A read before the data arrives blocks: try_io clears the readiness.
        let mut byte = [0_u8; 1];
        {
            let mut guard = fd.ready(Interest::both()).await.expect("ready");
            assert!(guard.is_writable(), "write readiness is kept");
            let early = guard.try_io(|fd| fd.get_ref().read(&mut byte).map(|_| ()));
            assert!(early.is_err(), "no data yet, so the read would block");
        }

        let started = Instant::now();
        let mut guard = fd.readable().await.expect("readable");
        assert!(guard.is_readable());
        let n = guard
            .try_io(|fd| fd.get_ref().read(&mut byte))
            .expect("data arrived")
            .expect("read");
        assert_eq!((n, byte[0]), (1, b'x'));
        assert!(started.elapsed() >= Duration::from_millis(200));
    });
    drop(writer.join().expect("writer"));
}

#[test]
fn write_readiness_returns_once_the_peer_drains_a_full_buffer() {
    let (mut local, peer) = nonblocking_pair();
    // Fill the socket buffer.
    let chunk = [7_u8; 4096];
    let mut filled = 0_usize;
    loop {
        match local.write(&chunk) {
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => panic!("fill: {err}"),
        }
    }
    let fd = AsyncFd::new(local).expect("wrap");
    let drainer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        let mut peer = peer;
        let mut sink = vec![0_u8; filled];
        peer.read_exact(&mut sink).expect("drain");
        peer
    });
    let started = Instant::now();
    let written = block_on(async {
        fd.async_io(Interest::WRITABLE, |stream| (&*stream).write(b"after"))
            .await
            .expect("write after drain")
    });
    assert!(written > 0);
    assert!(
        started.elapsed() >= Duration::from_millis(90),
        "the write waited for the drain: {:?}",
        started.elapsed()
    );
    drop(drainer.join().expect("drainer"));
}

#[test]
fn two_waiters_on_one_descriptor_are_both_woken() {
    let (local, peer) = nonblocking_pair();
    let fd = AsyncFd::new(local).expect("wrap");
    let writer = write_later(peer, Duration::from_millis(100), b"ab");
    let (first, second) = block_on(zip(
        async {
            let guard = fd.readable().await.expect("first waiter");
            guard.is_readable()
        },
        async {
            let guard = fd.readable().await.expect("second waiter");
            guard.is_readable()
        },
    ));
    assert!(first && second);
    drop(writer.join().expect("writer"));
}

#[test]
fn mutable_waits_and_into_inner_hand_back_the_descriptor() {
    let (local, peer) = nonblocking_pair();
    let raw = local.as_raw_fd();
    let mut fd = AsyncFd::new(local).expect("wrap");
    assert_eq!(fd.as_raw_fd(), raw);
    let writer = write_later(peer, Duration::from_millis(50), b"mut");
    let n = block_on(async {
        let mut buf = [0_u8; 8];
        let n = fd
            .async_io_mut(Interest::READABLE, |stream| stream.read(&mut buf))
            .await
            .expect("read");
        assert_eq!(&buf[..n], b"mut");
        let mut guard = fd.writable_mut().await.expect("writable");
        guard
            .try_io(|fd| fd.get_mut().write(b"!"))
            .expect("writable socket")
            .expect("write")
    });
    assert_eq!(n, 1);
    let mut peer = writer.join().expect("writer");
    let mut reply = [0_u8; 1];
    peer.read_exact(&mut reply).expect("peer read");
    assert_eq!(&reply, b"!");

    // The descriptor survives the wrapper and is still usable.
    let local = fd.into_inner();
    assert_eq!(local.as_raw_fd(), raw);
    peer.write_all(b"z").expect("peer write");
    let mut local = local;
    local.set_nonblocking(false).expect("blocking");
    let mut byte = [0_u8; 1];
    local.read_exact(&mut byte).expect("read after into_inner");
    assert_eq!(&byte, b"z");
}

#[test]
fn interest_without_a_direction_is_refused() {
    let (local, _peer) = nonblocking_pair();
    let fd = AsyncFd::new(local).expect("wrap");
    let error = block_on(async { fd.ready(Interest::empty()).await.map(|_| ()) })
        .expect_err("no direction");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn waiters_in_separate_tasks_on_a_multi_thread_runtime_are_all_woken() {
    let (local, peer) = nonblocking_pair();
    let fd = std::sync::Arc::new(AsyncFd::new(local).expect("wrap"));
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .build()
        .expect("build multi-thread runtime");
    let waiters: Vec<_> = (0..3)
        .map(|_| {
            let fd = std::sync::Arc::clone(&fd);
            runtime.handle().spawn(async move {
                let guard = fd.readable().await.expect("readable");
                guard.is_readable()
            })
        })
        .collect();
    // Let every task park before the data arrives.
    let writer = write_later(peer, Duration::from_millis(150), b"go");
    for waiter in waiters {
        assert!(runtime.block_on(waiter), "each task sees read readiness");
    }
    drop(writer.join().expect("writer"));
}

/// Forty tasks wait on one descriptor that stays idle, then all see it become
/// readable. Waiters past the 32nd used to evict and wake the oldest, which
/// re-registered and evicted the next, so the waiting tasks were re-polled
/// forever while nothing happened (br-asupersync-68jvck).
#[test]
fn forty_waiters_on_one_descriptor_park_until_it_is_ready() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (local, mut peer) = nonblocking_pair();
    let fd = Arc::new(AsyncFd::new(local).expect("wrap"));
    let polls = Arc::new(AtomicUsize::new(0));
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    let (idle_polls, woken) = runtime.block_on(async move {
        let waiters: Vec<_> = (0..40)
            .map(|_| {
                let fd = Arc::clone(&fd);
                let polls = Arc::clone(&polls);
                handle.spawn(async move {
                    let mut wait = std::pin::pin!(fd.readable());
                    std::future::poll_fn(|cx| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        wait.as_mut().poll(cx)
                    })
                    .await
                    .map(drop)
                })
            })
            .collect();
        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(300)).await;
        let idle_polls = polls.load(Ordering::SeqCst);
        peer.write_all(b"x").expect("peer write");
        let mut woken = 0;
        for waiter in waiters {
            waiter.await.expect("readable");
            woken += 1;
        }
        (idle_polls, woken)
    });
    eprintln!("forty waiters: {idle_polls} polls while idle, {woken} woken");
    assert_eq!(woken, 40);
    assert!(
        idle_polls < 200,
        "{idle_polls} polls while the descriptor was idle; each waiter should park"
    );
}
