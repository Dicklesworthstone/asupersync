//! Bounded writable input for the actual mutually authenticated live protocol.
//!
//! Writes admit bytes locally; flush waits for the peer's validated epoch
//! acknowledgement for every accepted byte. Finish closes input and joins the
//! worker's whole-stream Proof exchange. No spool or local queue counter is
//! substituted for remote acknowledgement.

use super::{
    LiveStreamError, LiveStreamReport, LiveStreamSender, LiveStreamTask, Progress, SendObserver,
    authorize,
};
use crate::cx::{Cx, Scope};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::JoinError;
use crate::types::{CancelReason, Policy};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// The canonical worker join and its retained whole-stream receipt or failure.
pub type LiveStreamWriterTerminal = Result<LiveStreamReport, JoinError>;

#[derive(Debug, Default)]
struct State {
    bytes: VecDeque<u8>,
    accepted: u64,
    acknowledged: u64,
    high_water: usize,
    eof: bool,
    aborted: bool,
    reader_gone: bool,
    reader_waker: Option<Waker>,
    writer_waker: Option<Waker>,
}

#[derive(Debug)]
struct Input {
    capacity: usize,
    state: Mutex<State>,
}

// Clone/drop/wake user Wakers outside the lock. A fresh candidate is installed
// only after rechecking readiness under the same lock as the state transition.
fn register(
    slot: &mut Option<Waker>,
    candidate: &mut Option<Waker>,
    current: &Waker,
) -> Option<Option<Waker>> {
    if slot.as_ref().is_some_and(|old| old.will_wake(current)) {
        Some(None)
    } else {
        candidate.take().map(|new| slot.replace(new))
    }
}

fn notify(waker: Option<Waker>) {
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "live stream writer is closed")
}

impl Input {
    fn new(capacity: usize) -> Arc<Self> {
        assert!(capacity > 0, "live stream input capacity must be nonzero");
        Arc::new(Self {
            capacity,
            state: Mutex::new(State::default()),
        })
    }

    fn poll_write(&self, ctx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let mut candidate = None;
        loop {
            let mut state = self.state.lock();
            if state.aborted || state.eof {
                return Poll::Ready(Err(closed()));
            }
            if state.reader_gone {
                // The facade has registered its canonical join waker. Retiring
                // the source can precede publication of a successful Proof or
                // the actual worker failure; do not invent an intermediate error.
                return Poll::Pending;
            }
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let count = bytes.len().min(self.capacity - state.bytes.len());
            if count != 0 {
                let Some(accepted) = state.accepted.checked_add(count as u64) else {
                    return Poll::Ready(Err(io::Error::other(
                        "live stream input byte counter exhausted",
                    )));
                };
                if let Err(error) = state.bytes.try_reserve(count) {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                state.bytes.extend(bytes[..count].iter().copied());
                state.accepted = accepted;
                state.high_water = state.high_water.max(state.bytes.len());
                let wake = state.reader_waker.take();
                let retired = state.writer_waker.take();
                drop(state);
                notify(wake);
                drop(retired);
                return Poll::Ready(Ok(count));
            }
            if let Some(retired) = register(&mut state.writer_waker, &mut candidate, ctx.waker()) {
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            drop(state);
            candidate = Some(ctx.waker().clone());
        }
    }

    fn poll_flush(&self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut candidate = None;
        loop {
            let mut state = self.state.lock();
            if state.aborted {
                return Poll::Ready(Err(closed()));
            }
            if state.reader_gone {
                return Poll::Pending;
            }
            if state.acknowledged == state.accepted {
                let retired = state.writer_waker.take();
                drop(state);
                drop(retired);
                return Poll::Ready(Ok(()));
            }
            if let Some(retired) = register(&mut state.writer_waker, &mut candidate, ctx.waker()) {
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            drop(state);
            candidate = Some(ctx.waker().clone());
        }
    }

    fn stop(&self, abort: bool) -> Option<Waker> {
        let mut state = self.state.lock();
        if abort {
            state.aborted = true;
            state.bytes.clear();
        } else {
            state.eof = true;
        }
        state.reader_waker.take()
    }

    fn clear_writer_waker(&self) {
        let retired = self.state.lock().writer_waker.take();
        drop(retired);
    }
}

impl SendObserver for Input {
    fn acknowledged(&self, bytes: u64) {
        let wake = {
            let mut state = self.state.lock();
            debug_assert!(bytes >= state.acknowledged && bytes <= state.accepted);
            state.acknowledged = bytes;
            state.writer_waker.take()
        };
        notify(wake);
    }
}

struct InputReader(Arc<Input>);

impl AsyncRead for InputReader {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut candidate = None;
        loop {
            let mut state = self.0.state.lock();
            if state.aborted {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "live stream producer aborted",
                )));
            }
            let count = buffer.remaining().min(state.bytes.len());
            if count != 0 {
                let (first, second) = state.bytes.as_slices();
                let first_len = count.min(first.len());
                buffer.put_slice(&first[..first_len]);
                buffer.put_slice(&second[..count - first_len]);
                drop(state.bytes.drain(..count));
                let wake = state.writer_waker.take();
                let retired = state.reader_waker.take();
                drop(state);
                notify(wake);
                drop(retired);
                return Poll::Ready(Ok(()));
            }
            if state.eof {
                let retired = state.reader_waker.take();
                drop(state);
                drop(retired);
                return Poll::Ready(Ok(()));
            }
            if let Some(retired) = register(&mut state.reader_waker, &mut candidate, ctx.waker()) {
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            drop(state);
            candidate = Some(ctx.waker().clone());
        }
    }
}

impl Drop for InputReader {
    fn drop(&mut self) {
        let (wake, retired) = {
            let mut state = self.0.state.lock();
            state.reader_gone = true;
            state.bytes.clear();
            (state.writer_waker.take(), state.reader_waker.take())
        };
        notify(wake);
        drop(retired);
    }
}

/// Writable input and the scope-owned worker transmitting it live.
///
/// Successful writes accept only their returned prefix into the bounded pipe;
/// Pending accepts nothing. The pipe holds at most `buffer_capacity()` unread
/// bytes in addition to the existing protocol's one in-flight epoch and bounded
/// TLS buffers. Writes may be transmitted before the producer reaches EOF.
///
/// `flush` waits until the peer has acknowledged sink flush for all accepted
/// bytes. This proves an acknowledged prefix, not whole-stream completion,
/// durable storage or an application transaction. `finish`/`shutdown` closes
/// input and waits for the exact final Proof through the real worker join.
///
/// The peer may narrow epoch/byte limits during negotiation. A local write can
/// therefore succeed before a later peer refusal; inspect the terminal report
/// and last acknowledged prefix before deciding how to recover. Input idleness
/// and peer backpressure remain subject to the configured operation timeout.
/// Dropping this writer requests cancellation, never successful EOF. The region
/// continues to own and drain the worker; no automatic retry is performed.
#[derive(Debug)]
#[must_use = "finish or cancel_and_wait; successful writes are not peer delivery"]
pub struct LiveStreamWriter {
    input: Arc<Input>,
    worker: LiveStreamTask,
    terminal: Option<LiveStreamWriterTerminal>,
}

impl LiveStreamSender {
    /// Reserve this sender's capacity and admit a bounded live producer.
    ///
    /// The new worker receives its actual child Cx. No socket is opened until
    /// the child runs, and no source bytes are consumed before authenticated
    /// negotiation. Immediate/deferred admission refusal retires the pipe and
    /// reservation; deferred failure is observable through I/O and `terminal()`.
    pub fn open_writer<P: Policy>(
        &self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        remote: SocketAddr,
    ) -> Result<LiveStreamWriter, LiveStreamError> {
        authorize(cx)?;
        let permit = self.admission.reserve()?;
        let input = Input::new(self.config.epoch_bytes);
        let observer = Arc::clone(&input);
        let mut reader = InputReader(Arc::clone(&input));
        let sender = self.clone();
        let worker = cx
            .spawn_in(scope, move |child| {
                let future: Pin<Box<dyn Future<Output = LiveStreamReport> + Send>> =
                    Box::pin(async move {
                        let _permit = permit;
                        let mut progress = Progress::default();
                        let outcome = match authorize(&child) {
                            Ok(()) => {
                                sender
                                    .send_inner(
                                        &child,
                                        remote,
                                        &mut reader,
                                        &mut progress,
                                        Some(observer.as_ref()),
                                    )
                                    .await
                            }
                            Err(error) => Err(error),
                        };
                        progress.report(outcome)
                    });
                future
            })
            .map_err(LiveStreamError::Spawn)?;
        Ok(LiveStreamWriter {
            input,
            worker,
            terminal: None,
        })
    }
}

impl LiveStreamWriter {
    /// Maximum unread input bytes, excluding the protocol's in-flight epoch.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        self.input.capacity
    }

    /// Current unread input bytes. Queue consumption is not a peer receipt.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.input.state.lock().bytes.len()
    }

    /// Peak unread bytes retained in the input pipe.
    #[must_use]
    pub fn buffer_high_water(&self) -> usize {
        self.input.state.lock().high_water
    }

    /// Total bytes accepted by successful writes, including unacknowledged input.
    #[must_use]
    pub fn accepted_bytes(&self) -> u64 {
        self.input.state.lock().accepted
    }

    /// Contiguous bytes covered by exact, validated peer epoch acknowledgements.
    /// This is a prefix observation, not whole-stream completion or durability.
    #[must_use]
    pub fn acknowledged_bytes(&self) -> u64 {
        self.input.state.lock().acknowledged
    }

    /// Collect and retain a ready canonical join without blocking or consuming it.
    #[must_use]
    pub fn terminal(&mut self) -> Option<&LiveStreamWriterTerminal> {
        if self.terminal.is_none() {
            match self.worker.try_join() {
                Ok(None) => {}
                Ok(Some(report)) => self.settle(Ok(report)),
                Err(error) => self.settle(Err(error)),
            }
        }
        self.terminal.as_ref()
    }

    /// Close input, transmit its remaining bytes and retain the final peer Proof.
    /// Dropping this wait preserves EOF, queued input and the canonical worker;
    /// a later finish resumes waiting. A finished writer cannot accept more bytes.
    pub async fn finish(&mut self) -> &LiveStreamWriterTerminal {
        notify(self.input.stop(false));
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined live stream sender")
    }

    /// Discard pending input, request cancellation and retain the actual join.
    /// Already acknowledged prefixes remain recorded. A peer may have consumed
    /// more than it acknowledged; cancellation is not rollback or retry authority.
    pub async fn cancel_and_wait(&mut self, reason: CancelReason) -> &LiveStreamWriterTerminal {
        if self.terminal().is_none() {
            self.worker.abort_with_reason(reason);
        }
        notify(self.input.stop(true));
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined live stream sender")
    }

    fn settle(&mut self, terminal: LiveStreamWriterTerminal) {
        self.terminal = Some(terminal);
        self.input.clear_writer_waker();
    }

    fn poll_terminal(&mut self, ctx: &mut Context<'_>) -> Poll<()> {
        if self.terminal.is_some() {
            return Poll::Ready(());
        }
        match self.worker.poll_join(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.settle(result);
                Poll::Ready(())
            }
        }
    }

    fn terminal_io_result(&self) -> io::Result<()> {
        match self
            .terminal
            .as_ref()
            .expect("terminal sender join observed")
        {
            Ok(report) => report.outcome.as_ref().map(|_| ()).map_err(|error| {
                let kind = match error {
                    LiveStreamError::Cancelled(_) => io::ErrorKind::Interrupted,
                    LiveStreamError::Timeout(_) => io::ErrorKind::TimedOut,
                    LiveStreamError::Protocol(_) | LiveStreamError::Frame(_) => {
                        io::ErrorKind::InvalidData
                    }
                    LiveStreamError::TooLarge(_) => io::ErrorKind::InvalidInput,
                    LiveStreamError::Io(error) => error.kind(),
                    _ => io::ErrorKind::Other,
                };
                io::Error::new(kind, error.to_string())
            }),
            Err(JoinError::Cancelled(reason)) => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("live sender worker cancelled: {reason}"),
            )),
            Err(error) => Err(io::Error::other(format!(
                "live sender worker failed: {error}"
            ))),
        }
    }
}

impl AsyncWrite for LiveStreamWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.poll_terminal(ctx).is_ready() {
            return Poll::Ready(self.terminal_io_result().and_then(|()| Err(closed())));
        }
        self.input.poll_write(ctx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_terminal(ctx).is_ready() {
            return Poll::Ready(self.terminal_io_result());
        }
        self.input.poll_flush(ctx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        notify(self.input.stop(false));
        match self.poll_terminal(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(self.terminal_io_result()),
        }
    }
}

impl Drop for LiveStreamWriter {
    fn drop(&mut self) {
        if self.terminal.is_none() && !self.worker.is_finished() {
            self.worker
                .abort_with_reason(CancelReason::user("live stream writer dropped"));
        }
        notify(self.input.stop(true));
        self.input.clear_writer_waker();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counter() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        (Arc::clone(&count), Waker::from(count))
    }
    fn ready<T: std::fmt::Debug>(poll: Poll<io::Result<T>>) -> T {
        match poll {
            Poll::Ready(Ok(value)) => value,
            other => panic!("expected success: {other:?}"),
        }
    }
    fn read(
        reader: &mut InputReader,
        ctx: &mut Context<'_>,
        count: usize,
    ) -> Poll<io::Result<Vec<u8>>> {
        let mut bytes = vec![0; count];
        let mut buffer = ReadBuf::new(&mut bytes);
        Pin::new(reader)
            .poll_read(ctx, &mut buffer)
            .map(|result| result.map(|()| buffer.filled().to_vec()))
    }

    #[test]
    fn flush_requires_peer_acknowledgement_even_after_the_source_queue_is_empty() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"data")), 4);
        assert_eq!(ready(read(&mut reader, &mut ctx, 4)), b"data");
        assert!(input.state.lock().bytes.is_empty());
        for _ in 0..20 {
            assert!(input.poll_flush(&mut ctx).is_pending());
        }
        assert_eq!(wake.0.load(Ordering::SeqCst), 0);
        input.acknowledged(3);
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.acknowledged(4);
        assert_eq!(wake.0.load(Ordering::SeqCst), 2);
        ready(input.poll_flush(&mut ctx));
    }

    #[test]
    fn bounded_writes_return_only_the_accepted_prefix_and_wake_after_reads() {
        let input = Input::new(3);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"abcdef")), 3);
        assert!(input.poll_write(&mut ctx, b"def").is_pending());
        assert_eq!(input.state.lock().accepted, 3);
        assert_eq!(ready(read(&mut reader, &mut ctx, 2)), b"ab");
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(ready(input.poll_write(&mut ctx, b"def")), 2);
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"cde");
        assert_eq!(input.state.lock().high_water, 3);
        assert_eq!(input.state.lock().accepted, 5);
        assert_eq!(input.state.lock().acknowledged, 0);
    }

    #[test]
    fn empty_input_parks_until_explicit_eof_and_eof_preserves_queued_bytes() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&mut reader, &mut ctx, 4).is_pending());
        assert_eq!(wake.0.load(Ordering::SeqCst), 0);
        assert_eq!(ready(input.poll_write(&mut ctx, b"data")), 4);
        notify(input.stop(false));
        assert_eq!(ready(read(&mut reader, &mut ctx, 4)), b"data");
        assert!(ready(read(&mut reader, &mut ctx, 4)).is_empty());
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.acknowledged(4);
        ready(input.poll_flush(&mut ctx));
        assert!(matches!(
            input.poll_write(&mut ctx, b"x"),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn aborted_input_wakes_a_pending_read_and_never_becomes_successful_eof() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&mut reader, &mut ctx, 4).is_pending());
        notify(input.stop(true));
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            read(&mut reader, &mut ctx, 4),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        assert!(matches!(input.poll_flush(&mut ctx), Poll::Ready(Err(_))));
    }

    #[test]
    fn retired_source_wakes_a_flush_but_leaves_terminal_classification_to_the_join() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"data")), 4);
        assert_eq!(ready(read(&mut reader, &mut ctx, 4)), b"data");
        input.acknowledged(4);
        assert_eq!(ready(input.poll_write(&mut ctx, b"next")), 4);
        assert!(input.poll_flush(&mut ctx).is_pending());
        drop(reader);
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(input.poll_flush(&mut ctx).is_pending());
        assert!(input.poll_write(&mut ctx, b"late").is_pending());
        let state = input.state.lock();
        assert!(state.bytes.is_empty());
        assert_eq!((state.accepted, state.acknowledged), (8, 4));
    }
}
