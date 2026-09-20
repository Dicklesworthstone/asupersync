//! Real native cancellation and loopback byte integrity for retained copy sessions.
//! The write gate intentionally withholds readiness after a committed prefix.
//! Cancellation must wake the copy without additional readiness from the gated
//! writer. No sleeps choose the schedule.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::io::{AsyncRead, AsyncWrite, BidirectionalCopySession, CopySession, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::Budget;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

const A_BYTES: &[u8] = b"request bytes must survive a cancelled forwarding future without loss or duplication";
const B_BYTES: &[u8] = b"the independent response direction must preserve its own prefix and EOF";

#[derive(Default)]
struct GateState { open: AtomicBool, blocked: AtomicBool }
struct Gated<S> { inner: S, state: Arc<GateState>, prefix: usize, written: usize }
impl<S: AsyncRead + Unpin> AsyncRead for Gated<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Gated<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let open = this.state.open.load(Ordering::Acquire);
        if !open && this.written == this.prefix {
            this.state.blocked.store(true, Ordering::Release);
            // Deliberately no I/O wake: the copy's owned cancellation registration
            // must wake the task. The next run is explicitly polled by its owner.
            return Poll::Pending;
        }
        let count = if open { bytes.len() } else { bytes.len().min(this.prefix - this.written) };
        let result = Pin::new(&mut this.inner).poll_write(cx, &bytes[..count]);
        if let Poll::Ready(Ok(n)) = &result { this.written += *n; }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn pair() -> (TcpStream, StdTcpStream) {
    // Explicit loopback fixtures established before runtime execution, not an
    // ambient network fallback inside the transfer implementation.
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

async fn witness_pending<T>(
    future: impl Future<Output = T>, state: &GateState, observed: oneshot::Sender<()>,
) -> T {
    let mut future = std::pin::pin!(future);
    let mut observed = Some(observed);
    poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        if result.is_pending() && state.blocked.load(Ordering::Acquire) {
            if let Some(observed) = observed.take() {
                // Signal only AFTER the actual copy future returned Pending with
                // its writer blocked, not on task submission or a timer guess.
                observed.send_blocking(()).unwrap();
            }
        }
        result
    }).await
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native copy session must terminate, including cancellation and peer cleanup");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

fn one_way(multithread: bool) {
    let (socket, mut peer) = pair();
    let receiver = std::thread::spawn(move || {
        let mut received = Vec::new();
        peer.read_to_end(&mut received).unwrap();
        received
    });
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let state = Arc::new(GateState::default());
        let gate = Gated { inner: socket, state: Arc::clone(&state), prefix: 7, written: 0 };
        let mut session = CopySession::with_capacity(A_BYTES, gate, 17).unwrap();
        let (observed, mut wait) = oneshot::channel();
        let worker_state = Arc::clone(&state);
        let mut task = owner.spawn(move |cx| async move {
            let result = witness_pending(session.run(&cx), &worker_state, observed).await;
            (session, result)
        }).unwrap();
        wait.recv(&owner).await.expect("witness an actual parked copy with read-ahead");
        task.abort();
        let (mut session, result) = task.join(&owner).await
            .expect("acknowledged cancellation must preserve the returned copy session");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        let paused = session.progress();
        assert_eq!(paused.written, 7);
        assert!(paused.buffered > 0);
        assert_eq!(paused.read - paused.written, paused.buffered as u64);
        assert_eq!(session.pending_bytes(), &A_BYTES[7..paused.read as usize]);
        state.open.store(true, Ordering::Release);
        assert_eq!(session.run(&owner).await.unwrap(), A_BYTES.len() as u64);
        assert!(session.is_complete());
        assert_eq!(session.run(&owner).await.unwrap(), A_BYTES.len() as u64);
        let (_, sink, pending) = session.into_parts();
        assert!(pending.is_empty());
        // Ordinary copy flushes, not shuts down. End the owned socket explicitly.
        drop(sink);
    });
    assert_eq!(receiver.join().unwrap(), A_BYTES);
    drop(runtime);
}

fn bidirectional(multithread: bool) {
    let (a, mut peer_a) = pair();
    let (b, mut peer_b) = pair();
    let peer_a = std::thread::spawn(move || {
        peer_a.write_all(A_BYTES).unwrap();
        peer_a.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        peer_a.read_to_end(&mut received).unwrap();
        received
    });
    let peer_b = std::thread::spawn(move || {
        peer_b.write_all(B_BYTES).unwrap();
        peer_b.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        peer_b.read_to_end(&mut received).unwrap();
        received
    });
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let state = Arc::new(GateState::default());
        let b = Gated { inner: b, state: Arc::clone(&state), prefix: 5, written: 0 };
        let mut session = BidirectionalCopySession::with_capacities(a, b, 19, 13).unwrap();
        let (observed, mut wait) = oneshot::channel();
        let worker_state = Arc::clone(&state);
        let mut task = owner.spawn(move |cx| async move {
            let result = witness_pending(session.run(&cx), &worker_state, observed).await;
            (session, result)
        }).unwrap();
        wait.recv(&owner).await.expect("witness actual duplex backpressure before abort");
        task.abort();
        let (mut session, result) = task.join(&owner).await
            .expect("cancelled task must return both retained directions");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        let paused = session.progress();
        assert_eq!(paused.a_to_b.written, 5);
        assert!(paused.a_to_b.buffered > 0);
        for direction in [paused.a_to_b, paused.b_to_a] {
            assert_eq!(direction.read - direction.written, direction.buffered as u64);
        }
        state.open.store(true, Ordering::Release);
        let totals = (A_BYTES.len() as u64, B_BYTES.len() as u64);
        assert_eq!(session.run(&owner).await.unwrap(), totals);
        assert!(session.is_complete());
        assert!(session.progress().a_to_b.write_shutdown);
        assert!(session.progress().b_to_a.write_shutdown);
        assert_eq!(session.run(&owner).await.unwrap(), totals);
    });
    assert_eq!(peer_a.join().unwrap(), B_BYTES);
    assert_eq!(peer_b.join().unwrap(), A_BYTES);
    drop(runtime);
}

#[test]
fn one_way_parked_cancellation_and_resume_current_thread() { bounded(|| one_way(false)); }
#[test]
fn one_way_parked_cancellation_and_resume_two_workers() { bounded(|| one_way(true)); }
#[test]
fn duplex_parked_cancellation_and_resume_current_thread() { bounded(|| bidirectional(false)); }
#[test]
fn duplex_parked_cancellation_and_resume_two_workers() { bounded(|| bidirectional(true)); }
