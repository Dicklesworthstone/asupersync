//! Behavioral proof that `fs::File`'s poll-based traits (`AsyncRead`,
//! `AsyncWrite`, `AsyncSeek`) offload their syscalls to the blocking pool
//! instead of running them on the async worker thread.
//!
//! The observable: on a single-worker runtime, a peer task keeps a counter
//! moving only while the worker is free during the file transfer. With pool
//! offload, pending 128 KiB chunk hops let the peer advance throughout one
//! `read_exact` of a 48 MiB buffer (384 chunks). On
//! a runtime built without a blocking pool (`blocking_threads(0, 0)`) the
//! offload degrades to the inline fallback: the only yields left are
//! `ReadExact`'s cooperative one every 32 polls (about 12 for this file), so
//! the peer advances an order of magnitude less. That contrast is the planted
//! negative and documents the pool requirement. A round-trip test proves
//! chunked writes, read-ahead left by an abandoned poll, the owned `seek`
//! (which must reconcile that read-ahead), and a write after read-ahead keep
//! the bytes and the cursor consistent.
//!
//! No-claim: this does not prove throughput, io_uring behaviour, or
//! semantics on non-regular files.

use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::Cx;
use asupersync::fs::{File, OpenOptions};
use asupersync::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
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

/// Reads `BIG` bytes through `read_exact` from a task that shares the single
/// worker with a peer task counting its own polls. Returns how many times the
/// peer ran strictly between the start and end of the reader's single
/// `read_exact` call, as observed by the reader itself.
///
/// The reader must be a spawned task: a `current_thread` runtime still drives
/// the `block_on` future on the caller's thread, separately from the worker
/// that runs spawned tasks, so blocking inside `block_on` would not starve
/// the peer and would prove nothing.
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

        let reader_ticks = Arc::clone(&ticks);
        let mut reader = cx
            .spawn(move |_task_cx| async move {
                // Let the peer start so that "ticks during the read" is
                // meaningful, then measure from inside this task only.
                for _ in 0..3 {
                    yield_now().await;
                }
                let mut file = File::open(&path).await.expect("open");
                let mut buf = vec![0u8; BIG];
                let before = reader_ticks.load(Ordering::SeqCst);
                file.read_exact(&mut buf).await.expect("read_exact");
                let after = reader_ticks.load(Ordering::SeqCst);
                assert_eq!(buf, pattern(BIG), "bytes must round-trip exactly");
                after - before
            })
            .expect("spawn reader");

        let progress = reader.join(&cx).await.expect("join reader");
        stop.store(true, Ordering::SeqCst);
        peer.join(&cx).await.expect("join peer");
        progress
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
        progress >= 100,
        "the peer task must advance roughly once per 128 KiB chunk (384 chunks) while the read is offloaded; ticks = {progress}"
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
    assert!(
        progress <= 40,
        "without a pool the syscalls run inline; only ReadExact's cooperative yield every 32 polls (about 12 here) lets the peer run; ticks = {progress}"
    );
}

#[cfg(feature = "test-internals")]
#[derive(Clone, Copy, Debug)]
enum RestrictedFileOperation {
    Read,
    Write,
    Seek,
}

/// Hold the actual file cursor operation on a blocking worker, then wake a
/// sibling on the sole async worker. The controller releases the operation even
/// on failure, so the old inline implementation fails without stranding a test
/// worker. No disk speed or number of cooperative yields is used as evidence.
#[cfg(feature = "test-internals")]
fn restricted_file_operation_keeps_worker_available(operation: RestrictedFileOperation) {
    use asupersync::channel::oneshot;
    use asupersync::cx::cap;
    use asupersync::fs::FileCursorOperationProbe;
    use std::future::{Future, poll_fn};

    let path = scratch_path(&format!("restricted-{operation:?}"));
    std::fs::write(&path, b"abcdef").expect("write restricted fixture");
    let native_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open restricted fixture");
    let probe = Arc::new(FileCursorOperationProbe::new());
    let mut file = File::from_std(native_file);
    file.install_cursor_operation_probe_for_test(Arc::clone(&probe));
    let (wake_peer, mut peer_woken) = oneshot::channel();
    let (peer_progress, observed_peer_progress) = std::sync::mpsc::channel();
    let controller_probe = Arc::clone(&probe);
    let controller = std::thread::spawn(move || {
        let blocked = controller_probe.wait_until_first_blocked(Duration::from_secs(5));
        let signalled = wake_peer.send_blocking(()).is_ok();
        let peer_thread = observed_peer_progress
            .recv_timeout(Duration::from_secs(5))
            .ok();
        controller_probe.release_first();
        (blocked, signalled, peer_thread)
    });
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()
        .expect("native runtime with one async worker and one blocking worker");
    let (io_thread, was_pending) = runtime.block_on(async move {
        let cx = Cx::current().expect("native root context");
        let mut peer = cx
            .spawn(move |peer_cx| async move {
                peer_woken.recv(&peer_cx).await.expect("controller wake");
                // Only sent after the controller observed the blocked syscall.
                let _ = peer_progress.send(std::thread::current().id());
            })
            .expect("spawn sibling before restricting I/O context");
        let mut io_task = cx
            .spawn(move |task_cx| async move {
                let io_thread = std::thread::current().id();
                let restricted = task_cx.restrict::<cap::None>();
                let mut operation_future = std::pin::pin!(async {
                    match operation {
                        RestrictedFileOperation::Read => {
                            let mut bytes = [0; 3];
                            file.read_exact(&mut bytes).await.expect("restricted read");
                            assert_eq!(&bytes, b"abc");
                        }
                        RestrictedFileOperation::Write => {
                            file.write_all(b"XYZ").await.expect("restricted write");
                        }
                        RestrictedFileOperation::Seek => {
                            assert_eq!(
                                AsyncSeekExt::seek(&mut file, SeekFrom::Start(3))
                                    .await
                                    .expect("restricted trait seek"),
                                3
                            );
                        }
                    }
                });
                let mut was_pending = false;
                poll_fn(|task| {
                    let _guard = restricted.clone().set_current_restricted();
                    let ambient = Cx::current().expect("restricted ambient context");
                    assert!(!ambient.capabilities().spawn);
                    assert!(ambient.blocking_pool_handle().is_none());
                    let poll = operation_future.as_mut().poll(task);
                    was_pending |= poll.is_pending();
                    poll
                })
                .await;
                (io_thread, was_pending)
            })
            .expect("spawn file task");
        let result = io_task.join(&cx).await.expect("join file task");
        peer.join(&cx).await.expect("join sibling");
        result
    });
    let (blocked, signalled, peer_thread) = controller.join().expect("join controller");
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    assert!(blocked, "the file operation must reach the cursor gate");
    assert!(signalled, "the controller must wake the sibling");
    assert!(
        was_pending,
        "the blocked file operation must return Pending"
    );
    assert_eq!(
        peer_thread,
        Some(io_thread),
        "the sibling must run on the same async worker before the file gate is released"
    );
    assert_eq!(probe.acquisition_count(), 1);
    let expected: &[u8] = match operation {
        RestrictedFileOperation::Write => b"XYZdef",
        RestrictedFileOperation::Read | RestrictedFileOperation::Seek => b"abcdef",
    };
    assert_eq!(
        std::fs::read(path).expect("read completed fixture"),
        expected
    );
    eprintln!(
        "bead=asupersync-bi2462.118 operation={operation:?} blocked={blocked} pending={was_pending} sibling_before_release=true cursor_acquisitions=1"
    );
}

#[cfg(feature = "test-internals")]
#[test]
fn restricted_read_offloads_while_a_native_sibling_progresses() {
    restricted_file_operation_keeps_worker_available(RestrictedFileOperation::Read);
}

#[cfg(feature = "test-internals")]
#[test]
fn restricted_write_offloads_while_a_native_sibling_progresses() {
    restricted_file_operation_keeps_worker_available(RestrictedFileOperation::Write);
}

#[cfg(feature = "test-internals")]
#[test]
fn restricted_seek_offloads_while_a_native_sibling_progresses() {
    restricted_file_operation_keeps_worker_available(RestrictedFileOperation::Seek);
}

#[test]
fn chunked_writes_read_ahead_and_relative_seek_stay_consistent() {
    let path = scratch_path("roundtrip");
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()
        .expect("runtime with a blocking pool");
    let expected = pattern(3 * 128 * 1024 + 7777);
    let path_for_task = path.clone();
    runtime.block_on(async move {
        // Read + write: `File::create` alone opens write-only.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path_for_task)
            .await
            .expect("create read/write");
        // Larger than one pool chunk, so write_all crosses several hops.
        file.write_all(&expected).await.expect("write_all");
        file.flush().await.expect("flush");

        // Create real read-ahead: queue a large read behind the occupied
        // blocking worker, then abandon that future before it completes. The
        // next, smaller read observes the completed syscall and must keep the
        // surplus bytes as read-ahead instead of dropping them.
        file.seek(SeekFrom::Start(0)).await.expect("seek start");
        let mut abandoned = vec![0u8; 128 * 1024];
        abandon_queued_io(file.read_exact(&mut abandoned)).await;
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
        abandon_queued_io(file.read_exact(&mut abandoned)).await;
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

async fn abandon_queued_io(future: impl std::future::Future) {
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut blocker = Box::pin(asupersync::runtime::spawn_blocking(move || {
        started_tx.send(()).expect("signal occupied pool worker");
        release_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("release occupied pool worker");
    }));
    std::future::poll_fn(|cx| {
        assert!(blocker.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("pool worker is occupied before submitting I/O");
    {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending(), "I/O is queued");
            std::task::Poll::Ready(())
        })
        .await;
    }
    release_tx.send(()).expect("release queued I/O");
    blocker.await;
}

fn check_poll_seek_after_abandoned_read(
    name: &str,
    seek: SeekFrom,
    expected_position: Option<usize>,
    abandon_seek: bool,
) {
    let path = scratch_path(name);
    let expected = pattern(1024);
    std::fs::write(&path, &expected).expect("write seek fixture");
    let mut observer = std::fs::File::open(&path).expect("open cursor observer");
    let mut file = File::from_std(observer.try_clone().expect("share OS cursor"));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()
        .expect("runtime with a blocking pool");

    runtime.block_on(async move {
        let mut abandoned = [0u8; 1024];
        abandon_queued_io(file.read(&mut abandoned)).await;
        let mut prefix = [0u8; 7];
        file.read_exact(&mut prefix)
            .await
            .expect("resume small read");
        assert_eq!(prefix, expected[..7]);
        assert_eq!(
            std::io::Seek::stream_position(&mut observer).expect("physical cursor"),
            1024,
            "the read completed and left 1017 real unread bytes"
        );

        // UFCS is intentional: File::seek is an owned-method path with a
        // different implementation. Exercise the AsyncSeek trait adapter.
        let result = if abandon_seek {
            abandon_queued_io(AsyncSeekExt::seek(&mut file, seek)).await;
            // A different trait operation must settle the abandoned seek,
            // including reporting its error, before another read can start.
            match file.flush().await {
                Ok(()) => AsyncSeekExt::stream_position(&mut file).await,
                Err(error) => Err(error),
            }
        } else {
            AsyncSeekExt::seek(&mut file, seek).await
        };
        let resume_at = match expected_position {
            Some(position) => {
                assert_eq!(result.expect("valid trait seek"), position as u64);
                position
            }
            None => {
                assert!(result.is_err(), "invalid seek must fail: {seek:?}");
                7
            }
        };
        let mut tail = Vec::new();
        file.read_to_end(&mut tail).await.expect("read after seek");
        assert_eq!(
            tail,
            expected[resume_at..],
            "seek must not lose unread bytes"
        );
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}

#[test]
fn poll_seek_rejected_relative_preserves_unread_bytes() {
    check_poll_seek_after_abandoned_read(
        "seek-rejected-relative",
        SeekFrom::Current(-8),
        None,
        false,
    );
}

#[test]
fn poll_seek_extreme_relative_preserves_unread_bytes() {
    check_poll_seek_after_abandoned_read(
        "seek-extreme-relative",
        SeekFrom::Current(i64::MIN),
        None,
        false,
    );
}

#[test]
fn poll_seek_rejected_end_preserves_unread_bytes() {
    check_poll_seek_after_abandoned_read("seek-rejected-end", SeekFrom::End(-1025), None, false);
}

#[test]
fn poll_seek_valid_positions_account_for_unread_bytes() {
    for (name, seek, position) in [
        ("seek-relative", SeekFrom::Current(-2), 5),
        ("seek-absolute", SeekFrom::Start(12), 12),
        ("seek-end", SeekFrom::End(-4), 1020),
    ] {
        check_poll_seek_after_abandoned_read(name, seek, Some(position), false);
    }
}

#[test]
fn poll_seek_abandoned_operation_settles_before_next_read() {
    check_poll_seek_after_abandoned_read(
        "seek-abandoned-valid",
        SeekFrom::Current(3),
        Some(10),
        true,
    );
    check_poll_seek_after_abandoned_read(
        "seek-abandoned-invalid",
        SeekFrom::Current(-8),
        None,
        true,
    );
}

#[test]
fn poll_seek_rejected_with_both_reader_and_file_buffers_preserves_bytes() {
    for (name, seek) in [
        ("buffered-seek-relative", SeekFrom::Current(-8)),
        ("buffered-seek-extreme", SeekFrom::Current(i64::MIN)),
        ("buffered-seek-end", SeekFrom::End(-1025)),
    ] {
        let path = scratch_path(name);
        let expected = pattern(1024);
        std::fs::write(&path, &expected).expect("write nested-buffer fixture");
        let mut observer = std::fs::File::open(&path).expect("open cursor observer");
        let file = File::from_std(observer.try_clone().expect("share OS cursor"));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .expect("runtime with a blocking pool");
        runtime.block_on(async move {
            let mut reader = BufReader::with_capacity(16, file);
            let mut abandoned = [0u8; 1024];
            abandon_queued_io(reader.read(&mut abandoned)).await;
            let mut prefix = [0u8; 7];
            reader.read_exact(&mut prefix).await.expect("read prefix");
            assert_eq!(prefix, expected[..7]);
            assert_eq!(reader.buffer(), &expected[7..16], "outer read-ahead");
            assert_eq!(
                std::io::Seek::stream_position(&mut observer).expect("physical cursor"),
                1024,
                "the inner File also retains unread bytes"
            );
            assert!(AsyncSeekExt::seek(&mut reader, seek).await.is_err());
            let mut tail = Vec::new();
            reader
                .read_to_end(&mut tail)
                .await
                .expect("read nested tail");
            assert_eq!(tail, expected[7..], "both buffers must resume without loss");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
    }
}
