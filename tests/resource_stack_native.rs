//! Native resource-scope acquisition, descendant drain and externally-woken LIFO release.
//! Bead: N/A. Scenario fixtures use explicit gates, not sleeps to choose a schedule.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::ChildRegionSpec;
use asupersync::cx::resource_bracket::BracketConfig;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::{Budget, Outcome};
use asupersync::Cx;
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

async fn witness_pending<F: Future>(future: F, witness: oneshot::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut witness = Some(witness);
    poll_fn(|task| {
        let result = future.as_mut().poll(task);
        if result.is_pending() {
            if let Some(witness) = witness.take() { witness.send_blocking(()).unwrap(); }
        }
        result
    }).await
}

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

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native scope must finish including peer and region cleanup");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

fn cancellation(multithread: bool, drop_handle: bool) {
    let (socket, mut peer) = pair();
    let (allow_ack, permitted) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut request = [0; 6];
        peer.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"CLOSE\n");
        // The owner permits this ONLY after observing the cleanup TCP read Pending.
        permitted.recv_timeout(Duration::from_secs(10)).unwrap();
        peer.write_all(b"A").unwrap();
        request
    });
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let events = Arc::new(Mutex::new(Vec::new()));
    let final_events = Arc::clone(&events);
    let descendant_done = Arc::new(AtomicBool::new(false));
    let final_done = Arc::clone(&descendant_done);
    runtime.block_on_with_cx(owner.clone(), async move {
        let boundary = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let mut orchestrator = boundary.cx().spawn(move |cx| async move {
            let (body_parked, mut body_wait) = oneshot::channel();
            let (child_parked, mut child_wait) = oneshot::channel();
            let (child_draining, mut draining_wait) = oneshot::channel();
            let (finish_child, mut child_gate) = oneshot::channel();
            let (cleanup_parked, mut cleanup_wait) = oneshot::channel();
            let work_events = Arc::clone(&events);
            let work_done = Arc::clone(&descendant_done);
            let mut handle = Some(cx.spawn_resource_scope::<(), &'static str, &'static str, _>(
                BracketConfig::new(64), 2,
                move |work_cx, mut resources| Box::pin(async move {
                    let old_events = Arc::clone(&work_events);
                    let old_done = Arc::clone(&work_done);
                    resources.try_insert(String::from("oldest"), move |_, value| async move {
                        assert!(old_done.load(Ordering::Acquire));
                        assert_eq!(value, "oldest");
                        // The newer socket release must already have observed its ACK.
                        let mut events = old_events.lock().unwrap();
                        assert_eq!(*events, ["socket"]);
                        events.push("oldest");
                        Outcome::Ok(())
                    }).unwrap();
                    let socket_events = Arc::clone(&work_events);
                    let socket_done = Arc::clone(&work_done);
                    resources.try_insert(socket, move |_, mut socket| async move {
                        assert!(socket_done.load(Ordering::Acquire), "release preceded descendant drain");
                        socket.write_all(b"CLOSE\n").await.unwrap();
                        socket.flush().await.unwrap();
                        let mut ack = [0; 1];
                        witness_pending(socket.read_exact(&mut ack), cleanup_parked).await.unwrap();
                        assert_eq!(&ack, b"A");
                        socket.shutdown().await.unwrap();
                        socket_events.lock().unwrap().push("socket");
                        // Even a typed release failure must not skip the older resource.
                        Outcome::Err("newer release application failure")
                    }).unwrap();
                    let _descendant = work_cx.spawn(move |child| async move {
                        let (_keep, mut stop) = oneshot::channel::<()>();
                        let result = witness_pending(stop.recv(&child), child_parked).await;
                        assert!(matches!(result, Err(oneshot::RecvError::Cancelled)));
                        witness_pending(child_gate.recv_uninterruptible(), child_draining).await.unwrap();
                        work_done.store(true, Ordering::Release);
                    }).unwrap();
                    let (_keep, mut stop) = oneshot::channel::<()>();
                    let result = witness_pending(stop.recv(&work_cx), body_parked).await;
                    assert!(matches!(result, Err(oneshot::RecvError::Cancelled)));
                    Outcome::Cancelled(work_cx.cancel_reason().unwrap())
                }),
            ).unwrap());
            body_wait.recv(&cx).await.unwrap();
            child_wait.recv(&cx).await.unwrap();
            if drop_handle { drop(handle.take()); }
            else { handle.as_ref().unwrap().abort(); }
            draining_wait.recv(&cx).await.unwrap();
            assert!(!descendant_done.load(Ordering::Acquire));
            assert!(events.lock().unwrap().is_empty());
            assert!(matches!(cleanup_wait.try_recv(), Err(oneshot::TryRecvError::Empty)),
                "a blocked descendant prevents resource release");
            finish_child.send_blocking(()).unwrap();
            cleanup_wait.recv(&cx).await.expect("release must actually park awaiting peer ACK");
            assert!(descendant_done.load(Ordering::Acquire));
            assert!(events.lock().unwrap().is_empty(), "older release must wait for newer release");
            if let Some(handle) = &mut handle {
                for _ in 0..3 {
                    let mut join = std::pin::pin!(handle.join());
                    poll_fn(|task| {
                        assert!(join.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                }
            }
            allow_ack.send(()).unwrap();
            if let Some(handle) = &mut handle {
                let report = handle.join().await.unwrap();
                assert!(!report.is_success());
                assert!(report.lifecycle.close.as_ref().unwrap().is_ok());
                assert!(matches!(report.lifecycle.body_task, Some(Ok(()))));
                assert!(matches!(&report.lifecycle.usage.as_ref().unwrap().outcome, Outcome::Cancelled(_)));
                assert!(report.lifecycle.cancellation.is_some());
                assert!(matches!(&report.lifecycle.release.as_ref().unwrap().outcome, Outcome::Err(())));
                let cleanup = report.cleanup.unwrap();
                assert!(cleanup.complete);
                assert_eq!(cleanup.entries.iter().map(|entry| entry.index).collect::<Vec<_>>(), [1, 0]);
                assert!(matches!(&cleanup.entries[0].phase.outcome, Outcome::Err("newer release application failure")));
                assert!(cleanup.entries[1].phase.is_success());
                assert!(report.lifecycle.unreleased.is_none());
                assert!(report.lifecycle.controller_task.is_ok());
            }
        }).unwrap();
        orchestrator.join(&owner).await.unwrap();
        // In handle-Drop cases this is the authoritative remaining controller
        // drain barrier; no handle join was used to make the cleanup happen.
        boundary.close().await.unwrap();
    });
    assert!(final_done.load(Ordering::Acquire));
    assert_eq!(*final_events.lock().unwrap(), ["socket", "oldest"]);
    assert_eq!(&peer.join().unwrap(), b"CLOSE\n");
}

fn startup_failure(multithread: bool) {
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let boundary = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let mut task = boundary.cx().spawn(|cx: Cx| async move {
            let mut scope = cx.spawn_resource_scope::<(), &'static str, &'static str, _>(
                BracketConfig::new(8), 3,
                |cx, mut resources| Box::pin(async move {
                    let phase = resources.reserve().unwrap().acquire(
                        &cx, |_| async { Outcome::<_, &'static str>::Ok(Cell::new(19_u8)) },
                        |_, resource| async move { assert_eq!(resource.get(), 23); Outcome::Ok(()) },
                    ).await;
                    assert!(phase.is_success());
                    let Outcome::Ok(key) = phase.outcome else { panic!("first acquisition"); };
                    resources.get(&key).unwrap().set(23);
                    resources.try_insert(String::from("second"), |_, resource| async move {
                        assert_eq!(resource, "second");
                        panic!("newer resource release panic");
                        #[allow(unreachable_code)]
                        Outcome::<(), &'static str>::Ok(())
                    }).unwrap();
                    let failed = resources.reserve().unwrap().acquire(
                        &cx, |_| async { Outcome::<u8, _>::Err("third acquisition failed") },
                        |_, _| -> std::future::Ready<Outcome<(), &'static str>> {
                            panic!("third resource was never acquired");
                        },
                    ).await;
                    match failed.outcome {
                        Outcome::Err(error) => Outcome::Err(error),
                        _ => panic!("expected original acquisition failure"),
                    }
                }),
            ).unwrap();
            let report = scope.join().await.unwrap();
            assert!(!report.is_success());
            assert!(matches!(&report.lifecycle.usage.as_ref().unwrap().outcome,
                Outcome::Err("third acquisition failed")));
            assert!(report.lifecycle.close.as_ref().unwrap().is_ok());
            let cleanup = report.cleanup.unwrap();
            assert!(cleanup.complete);
            assert_eq!(cleanup.entries.iter().map(|entry| entry.index).collect::<Vec<_>>(), [1, 0]);
            assert!(matches!(&cleanup.entries[0].phase.outcome,
                Outcome::Panicked(p) if p.message() == "newer resource release panic"));
            assert!(cleanup.entries[1].phase.is_success());
        }).unwrap();
        task.join(&owner).await.unwrap();
        boundary.close().await.unwrap();
    });
}

#[test]
fn abort_drains_descendants_then_awaits_lifo_tcp_cleanup_current_thread() { bounded(|| cancellation(false, false)); }
#[test]
fn abort_drains_descendants_then_awaits_lifo_tcp_cleanup_two_workers() { bounded(|| cancellation(true, false)); }
#[test]
fn handle_drop_retains_lifo_tcp_cleanup_until_region_close_current_thread() { bounded(|| cancellation(false, true)); }
#[test]
fn handle_drop_retains_lifo_tcp_cleanup_until_region_close_two_workers() { bounded(|| cancellation(true, true)); }
#[test]
fn failed_startup_keeps_original_error_and_releases_older_resources_current_thread() { bounded(|| startup_failure(false)); }
#[test]
fn failed_startup_keeps_original_error_and_releases_older_resources_two_workers() { bounded(|| startup_failure(true)); }
