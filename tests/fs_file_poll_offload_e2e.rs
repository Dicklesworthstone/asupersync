//! Behavioral proof that `fs::File`'s poll-based traits (`AsyncRead`,
//! `AsyncWrite`, `AsyncSeek`) offload their syscalls to the blocking pool
//! instead of running them on the async worker thread.
//!
//! The observable: on a single-worker runtime, a peer task keeps a counter
//! moving only if the worker is free while the file transfer is in flight.
//! With pool offload every chunk hop returns `Pending`, so the peer advances
//! during one `read_exact` of a large buffer. On a runtime built without a
//! blocking pool (`blocking_threads(0, 0)`) the offload degrades to the inline
//! fallback and the peer cannot advance inside that single `read_exact` poll;
//! that case is the planted negative and documents the pool requirement.
//! Round-trip tests prove chunked writes, read-ahead handling, and relative
//! seeks keep the bytes and cursor consistent.
//!
//! No-claim: this does not prove throughput, io_uring behaviour, or
//! semantics on non-regular files.

use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::Cx;
use asupersync::fs::File;
use asupersync::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use asupersync::runtime::{RuntimeBuilder, yield_now};

const BIG: usize = 48 * 1024 * 1024;

fn scratch_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "asupersync-fs-poll-offload-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir.join("data.bin")
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Reads `BIG` bytes through `read_exact` while a peer task counts yields.
/// Returns how many times the peer ran strictly between the start and end of
/// the single `read_exact` call.
fn peer_progress_during_read_exact(
    runtime: asupersync::runtime::Runtime,
    path: &std::path::Path,
) -> usize {
    let path = path.to_path_buf();
    runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let stop = Arc::new(AtomicBool::new(false));
        let ticks = Arc::new(AtomicUsize::new(0));
        let (peer_stop, peer_ticks) = (Arc::clone(&stop), Arc::clone(&ticks));
        let mut peer = cx
            .spawn(move |_task_cx| async move {
                while !peer_stop.load(Ordering::SeqCst) {
                    peer_ticks.fetch_add(1, Ordering::SeqCst);
                    yield_now().await;
                }
            })
            .expect("spawn peer");
        // Let the peer start so that "ticks during the read" is meaningful.
        for _ in 0..3 {
            yield_now().await;
        }

        let mut file = File::open(&path).await.expect("open");
        let mut buf = vec![0u8; BIG];
        let before = ticks.load(Ordering::SeqCst);
        file.read_exact(&mut buf).await.expect("read_exact");
        let after = ticks.load(Ordering::SeqCst);
        assert_eq!(buf, pattern(BIG), "bytes must round-trip exactly");

        stop.store(true, Ordering::SeqCst);
        peer.join(&cx).await.expect("join peer");
        after - before
    })
}

#[test]
fn read_exact_lets_a_peer_task_run_when_a_blocking_pool_exists() {
    let path = scratch_path("offload");
    std::fs::write(&path, pattern(BIG)).expect("write fixture");
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 2)
        .build()
        .expect("runtime with a blocking pool");
    let progress = peer_progress_during_read_exact(runtime, &path);
    assert!(
        progress > 0,
        "the peer task must advance while the file read is offloaded; ticks = {progress}"
    );
}

#[test]
fn read_exact_starves_the_peer_without_a_blocking_pool_planted_negative() {
    let path = scratch_path("inline");
    std::fs::write(&path, pattern(BIG)).expect("write fixture");
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime without a blocking pool");
    let progress = peer_progress_during_read_exact(runtime, &path);
    assert_eq!(
        progress, 0,
        "without a pool the syscalls run inline in one poll, so the peer cannot advance"
    );
}

#[test]
fn chunked_writes_read_ahead_and_relative_seek_stay_consistent() {
    let path = scratch_path("roundtrip");
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 2)
        .build()
        .expect("runtime with a blocking pool");
    let expected = pattern(3 * 128 * 1024 + 7777);
    let path_for_task = path.clone();
    runtime.block_on(async move {
        let mut file = File::create(&path_for_task).await.expect("create");
        // Larger than one pool chunk, so write_all crosses several hops.
        file.write_all(&expected).await.expect("write_all");
        file.flush().await.expect("flush");

        // Create real read-ahead: start a large read, poll it exactly once so
        // a 128 KiB pool syscall is in flight, then abandon that future. The
        // next, smaller read observes the completed syscall and must keep the
        // surplus bytes as read-ahead instead of dropping them.
        file.seek(SeekFrom::Start(0)).await.expect("seek start");
        let mut abandoned = vec![0u8; 128 * 1024];
        {
            let mut in_flight = Box::pin(file.read_exact(&mut abandoned));
            std::future::poll_fn(|poll_cx| {
                let first = in_flight.as_mut().poll(poll_cx);
                assert!(
                    first.is_pending(),
                    "with a pool the first poll must submit the syscall and return Pending"
                );
                std::task::Poll::Ready(())
            })
            .await;
        }
        let mut head = [0u8; 100];
        file.read_exact(&mut head).await.expect("read head");
        assert_eq!(&head[..], &expected[..100]);
        let pos = file
            .seek(SeekFrom::Current(50))
            .await
            .expect("relative seek past read-ahead");
        assert_eq!(
            pos, 150,
            "cursor must be measured from the caller's position"
        );
        let mut mid = [0u8; 64];
        file.read_exact(&mut mid)
            .await
            .expect("read after relative seek");
        assert_eq!(&mid[..], &expected[150..214]);

        // Write after a read left read-ahead behind: the write must land at
        // the caller's cursor, not past the read-ahead.
        file.seek(SeekFrom::Start(1000)).await.expect("seek 1000");
        {
            let mut in_flight = Box::pin(file.read_exact(&mut abandoned));
            std::future::poll_fn(|poll_cx| {
                assert!(in_flight.as_mut().poll(poll_cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        let mut probe = [0u8; 10];
        file.read_exact(&mut probe).await.expect("read probe");
        assert_eq!(&probe[..], &expected[1000..1010]);
        file.write_all(b"XYZ").await.expect("write after read");
        file.flush().await.expect("flush");
        let all = std::fs::read(&path_for_task).expect("reread file");
        assert_eq!(
            &all[1010..1013],
            b"XYZ",
            "write must land at the caller's cursor"
        );
        assert_eq!(&all[..1010], &expected[..1010]);
        assert_eq!(&all[1013..], &expected[1013..]);
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}
