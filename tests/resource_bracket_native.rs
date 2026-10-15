//! Native release must park for real socket readiness after observed cancellation.
//! No sleeps select the race. The peer cannot acknowledge cleanup until the
//! release future has reported a real Pending read on the runtime's TCP stream.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::resource_bracket::{BracketConfig, BracketUseFuture};
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::{Budget, Outcome};
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};
use std::time::Duration;

const RELEASE: &[u8] = b"release-after-use-subtree-drained";

fn pair() -> (TcpStream, StdTcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (local, _) = listener.accept().unwrap();
    local.set_nonblocking(true).unwrap();
    local.set_nodelay(true).unwrap();
    peer.set_nodelay(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    (TcpStream::from_std(local).unwrap(), peer)
}

// Watchdog bounds the test process wait, not the bracket's cleanup semantics.
fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native bracket must finish its observed cleanup and region drain");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

fn exercise(multithread: bool, drop_handle: bool) {
    // Explicit loopback fixtures, established before runtime execution.
    let (socket, mut peer) = pair();
    let (allow_ack, await_permission) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut bytes = vec![0; RELEASE.len()];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, RELEASE);
        await_permission.recv_timeout(Duration::from_secs(10)).unwrap();
        peer.write_all(b"!").unwrap();
        let mut tail = Vec::new();
        peer.read_to_end(&mut tail).unwrap();
        assert!(tail.is_empty(), "release must not duplicate its protocol write");
    });
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let enclosing = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let (use_parked, mut wait_use) = oneshot::channel();
        let (release_parked, mut wait_release) = oneshot::channel();
        let (released, mut wait_released) = oneshot::channel();
        let completions = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&completions);
        let handle = enclosing.cx().spawn_bracket(BracketConfig::new(u32::MAX),
            move |_| async move { Outcome::<_, &'static str>::Ok(socket) },
            move |use_cx: Cx, _socket: &mut TcpStream| -> BracketUseFuture<'_, (), &'static str> {
                Box::pin(async move {
                    let mut observed = Some(use_parked);
                    let mut cancelled = std::pin::pin!(use_cx.cancelled());
                    poll_fn(|task_cx| {
                        let poll = cancelled.as_mut().poll(task_cx);
                        if poll.is_pending() {
                            if let Some(observed) = observed.take() {
                                observed.send_blocking(()).unwrap();
                            }
                        }
                        poll
                    }).await;
                    assert!(use_cx.checkpoint().is_err(), "acknowledge actual task cancellation");
                    Outcome::Cancelled(use_cx.cancel_reason().unwrap())
                })
            },
            move |release_cx: Cx, mut socket: TcpStream| async move {
                assert!(release_cx.checkpoint().is_ok(), "release poll is masked");
                let result: io::Result<()> = async {
                    socket.write_all(RELEASE).await?;
                    socket.flush().await?;
                    let mut acknowledgement = [0];
                    {
                        let mut read = std::pin::pin!(socket.read_exact(&mut acknowledgement));
                        let mut observed = Some(release_parked);
                        poll_fn(|task_cx| {
                            let poll = read.as_mut().poll(task_cx);
                            if poll.is_pending() {
                                if let Some(observed) = observed.take() {
                                    // The peer is forbidden to send its ACK until this
                                    // real AsyncRead future has returned Pending.
                                    observed.send_blocking(()).unwrap();
                                }
                            }
                            poll
                        }).await?;
                    }
                    assert_eq!(acknowledgement, *b"!");
                    // Async write-half shutdown (AsyncWriteExt); the inherent
                    // TcpStream::shutdown(how) would shadow it. br-asupersync-ymj7j3.
                    AsyncWriteExt::shutdown(&mut socket).await?;
                    Ok(())
                }.await;
                match result {
                    Ok(()) => {
                        count.fetch_add(1, Ordering::SeqCst);
                        released.send_blocking(()).unwrap();
                        Outcome::Ok(())
                    }
                    Err(error) => Outcome::Err(error),
                }
            },
        ).unwrap();
        wait_use.recv(&owner).await.expect("use task really parked before stop");
        let mut handle = if drop_handle {
            drop(handle);
            None
        } else {
            handle.abort();
            Some(handle)
        };
        wait_release.recv(&owner).await.expect("release really waits for network readiness after stop");
        assert_eq!(completions.load(Ordering::SeqCst), 0);
        if let Some(handle) = &mut handle {
            for _ in 0..3 {
                let mut joining = std::pin::pin!(handle.join());
                assert!(joining.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            }
        }
        allow_ack.send(()).unwrap();
        wait_released.recv(&owner).await.expect("real asynchronous release completes");
        if let Some(handle) = &mut handle {
            let report = handle.join().await.unwrap();
            assert!(report.acquisition.as_ref().unwrap().is_success());
            assert!(report.usage.as_ref().unwrap().outcome.is_cancelled());
            assert!(report.close.as_ref().unwrap().is_ok());
            assert!(report.release.as_ref().unwrap().is_success());
            assert!(report.unreleased.is_none());
            assert!(report.infrastructure.is_empty());
            assert!(report.cancellation.is_some());
            assert!(!report.is_success(), "completed cleanup cannot turn cancellation into success");
        }
        // Also supplies the barrier in the handle-drop case: the release
        // notification alone is not a claim that its controller already joined.
        enclosing.close().await.unwrap();
        assert_eq!(completions.load(Ordering::SeqCst), 1);
    });
    peer.join().unwrap();
    drop(runtime);
}

#[test]
fn cancelled_bracket_awaits_socket_release_current_thread() { bounded(|| exercise(false, false)); }
#[test]
fn cancelled_bracket_awaits_socket_release_two_workers() { bounded(|| exercise(true, false)); }
#[test]
fn dropped_bracket_handle_keeps_socket_release_region_owned_current_thread() { bounded(|| exercise(false, true)); }
#[test]
fn dropped_bracket_handle_keeps_socket_release_region_owned_two_workers() { bounded(|| exercise(true, true)); }
