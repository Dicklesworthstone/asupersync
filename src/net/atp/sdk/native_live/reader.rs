//! Pull-based receipt of verified live epochs with bounded backpressure.
//!
//! The existing mutually authenticated protocol validates every epoch before
//! writing it to this pipe. Its flush waits for the reader to consume those
//! bytes, so a slow reader delays the epoch acknowledgement and the sender's
//! next source read. Whole-stream success still requires the canonical worker
//! result: neither an empty queue nor the producer disappearing means EOF.

use super::{LiveStreamError, LiveStreamListener, LiveStreamReport, LiveStreamTask, authorize};
use crate::cx::{Cx, Scope};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::JoinError;
use crate::types::{CancelReason, Policy};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// The actual worker join and its retained protocol receipt or failure.
pub type LiveStreamReaderTerminal = Result<LiveStreamReport, JoinError>;

#[derive(Debug, Default)]
struct State {
    bytes: VecDeque<u8>,
    accepted: u64,
    consumed: u64,
    high_water: usize,
    aborted: bool,
    reader_waker: Option<Waker>,
    writer_waker: Option<Waker>,
}

#[derive(Debug)]
struct Output {
    capacity: usize,
    state: Mutex<State>,
}

// RawWaker clone/drop can call arbitrary user code. Clone outside the lock,
// then recheck readiness before installing the candidate under that same lock.
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

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "live stream reader is closed")
}

impl Output {
    fn new(capacity: usize) -> Arc<Self> {
        assert!(capacity > 0, "live stream output capacity must be nonzero");
        Arc::new(Self {
            capacity,
            state: Mutex::new(State::default()),
        })
    }

    fn poll_write(&self, ctx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let mut candidate = None;
        loop {
            let mut state = self.state.lock();
            if state.aborted {
                return Poll::Ready(Err(stopped()));
            }
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let count = bytes.len().min(self.capacity - state.bytes.len());
            if count != 0 {
                let Some(accepted) = state.accepted.checked_add(count as u64) else {
                    return Poll::Ready(Err(io::Error::other(
                        "live stream byte counter exhausted",
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
                return Poll::Ready(Err(stopped()));
            }
            if state.bytes.is_empty() {
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

    // An empty pipe is always Pending. Only its owner's canonical joined
    // protocol outcome may turn that empty pipe into EOF or a terminal error.
    fn poll_read(&self, ctx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<()> {
        let mut candidate = None;
        loop {
            let mut state = self.state.lock();
            let count = buffer.remaining().min(state.bytes.len());
            if count != 0 {
                let (first, second) = state.bytes.as_slices();
                let first_len = count.min(first.len());
                buffer.put_slice(&first[..first_len]);
                buffer.put_slice(&second[..count - first_len]);
                drop(state.bytes.drain(..count));
                // Consumed bytes cannot exceed the checked accepted counter.
                state.consumed += count as u64;
                let wake = state.writer_waker.take();
                let retired = state.reader_waker.take();
                drop(state);
                notify(wake);
                drop(retired);
                return Poll::Ready(());
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

    fn abort(&self) {
        let (wake, retired) = {
            let mut state = self.state.lock();
            state.aborted = true;
            state.bytes.clear();
            (state.writer_waker.take(), state.reader_waker.take())
        };
        notify(wake);
        drop(retired);
    }

    fn clear_reader_waker(&self) {
        let retired = self.state.lock().reader_waker.take();
        drop(retired);
    }
}

struct OutputSink(Arc<Output>);

impl AsyncWrite for OutputSink {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_write(ctx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_flush(ctx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_flush(ctx)
    }
}

impl Drop for OutputSink {
    fn drop(&mut self) {
        let (wake, retired) = {
            let mut state = self.0.state.lock();
            // Keep already verified, unread bytes available after failure.
            (state.reader_waker.take(), state.writer_waker.take())
        };
        notify(wake);
        drop(retired);
    }
}

/// A bounded byte reader and the real scope-owned receiver that feeds it.
///
/// Each returned byte belongs to an authenticated, hash-verified epoch. Bytes
/// are a prefix until the whole-stream commitment and final Proof complete.
/// Empty reads with a nonempty destination mean successful whole-stream EOF;
/// a failed worker, invalid final commitment, timeout or cancellation is an
/// error, never EOF. Already queued verified bytes are returned before a worker
/// failure; explicit cancellation discards unread bytes.
///
/// The queue retains at most one configured epoch. An epoch is acknowledged
/// only after the application consumes it, without claiming persistence or
/// application commit. The receiver's operation timeout applies while the
/// application leaves an epoch unread. Protocol/TLS buffers are separately
/// bounded by the existing transport and are not included in queue counters.
///
/// Dropping a read future consumes no bytes if its poll returned Pending.
/// Dropping this handle requests cancellation; the owning region still drains
/// its worker. Use `cancel_and_wait` when joined termination must be observed.
#[derive(Debug)]
#[must_use = "read to EOF or cancel_and_wait; a verified prefix is not stream completion"]
pub struct LiveStreamReader {
    output: Arc<Output>,
    worker: LiveStreamTask,
    terminal: Option<LiveStreamReaderTerminal>,
}

impl LiveStreamListener {
    /// Move this bound listener into a scoped receiver and expose verified bytes.
    ///
    /// Retains the existing admission slot and socket through worker completion.
    /// No second reservation or detached pump is created. Deferred admission and
    /// TLS/protocol failures are observable through reads and `terminal()`.
    /// An immediate refusal retires the listener, queue and admission together.
    pub fn open_reader<P: Policy>(
        self,
        cx: &Cx,
        scope: &Scope<'_, P>,
    ) -> Result<LiveStreamReader, LiveStreamError> {
        authorize(cx)?;
        let output = Output::new(self.receiver.config.epoch_bytes);
        let worker = self.spawn_receive_into(cx, scope, OutputSink(Arc::clone(&output)))?;
        Ok(LiveStreamReader {
            output,
            worker,
            terminal: None,
        })
    }
}

impl LiveStreamReader {
    /// Maximum unread bytes in this pipe, excluding TLS/protocol buffers.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        self.output.capacity
    }

    /// Current unread verified bytes; zero is not a completion signal.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.output.state.lock().bytes.len()
    }

    /// Peak unread bytes retained in this pipe.
    #[must_use]
    pub fn buffer_high_water(&self) -> usize {
        self.output.state.lock().high_water
    }

    /// Verified epoch bytes accepted into the pipe, including unread bytes.
    /// This is the same sink boundary counted by the worker's report.
    #[must_use]
    pub fn received_bytes(&self) -> u64 {
        self.output.state.lock().accepted
    }

    /// Bytes actually returned to callers of `AsyncRead`.
    #[must_use]
    pub fn consumed_bytes(&self) -> u64 {
        self.output.state.lock().consumed
    }

    /// Collect a ready canonical join without consuming its retained evidence.
    /// This never interprets an empty pipe as a finished transfer.
    #[must_use]
    pub fn terminal(&mut self) -> Option<&LiveStreamReaderTerminal> {
        if self.terminal.is_none() {
            match self.worker.try_join() {
                Ok(None) => {}
                Ok(Some(report)) => self.settle(Ok(report)),
                Err(error) => self.settle(Err(error)),
            }
        }
        self.terminal.as_ref()
    }

    /// Await and retain the actual protocol result without consuming payload.
    ///
    /// Read to EOF before using this to wait for success: the worker intentionally
    /// waits for unread bytes to be consumed before acknowledging their epoch.
    /// Dropping this wait preserves the reader, worker and canonical join.
    pub async fn wait_terminal(&mut self) -> &LiveStreamReaderTerminal {
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined live receiver")
    }

    /// Discard unread bytes, request cancellation, and join the receiver.
    ///
    /// Already delivered prefixes and the exact terminal report remain available.
    /// Cancellation is cooperative; it cannot preempt nonreturning user code.
    /// A worker that completed first keeps its original successful receipt.
    pub async fn cancel_and_wait(&mut self, reason: CancelReason) -> &LiveStreamReaderTerminal {
        if self.terminal().is_none() {
            // Publish cancellation attribution before the sink observes abort.
            self.worker.abort_with_reason(reason);
        }
        self.output.abort();
        self.wait_terminal().await
    }

    fn settle(&mut self, terminal: LiveStreamReaderTerminal) {
        self.terminal = Some(terminal);
        self.output.clear_reader_waker();
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
            .expect("terminal receiver join observed")
        {
            Ok(report) => report.outcome.as_ref().map(|_| ()).map_err(|error| {
                let kind = match error {
                    LiveStreamError::Cancelled(_) => io::ErrorKind::Interrupted,
                    LiveStreamError::Timeout(_) => io::ErrorKind::TimedOut,
                    LiveStreamError::Protocol(_) | LiveStreamError::Frame(_) => {
                        io::ErrorKind::InvalidData
                    }
                    LiveStreamError::TooLarge(_) => io::ErrorKind::InvalidData,
                    LiveStreamError::Io(error) => error.kind(),
                    _ => io::ErrorKind::Other,
                };
                io::Error::new(kind, error.to_string())
            }),
            Err(JoinError::Cancelled(reason)) => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("live receiver worker cancelled: {reason}"),
            )),
            Err(error) => Err(io::Error::other(format!(
                "live receiver worker failed: {error}"
            ))),
        }
    }
}

impl AsyncRead for LiveStreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Register for canonical completion even when the worker never reaches
        // its sink (deferred admission refusal, TLS error or early cancellation).
        let terminal = self.poll_terminal(ctx).is_ready();
        if self.output.poll_read(ctx, buffer).is_ready() {
            return Poll::Ready(Ok(()));
        }
        if terminal {
            self.output.clear_reader_waker();
            Poll::Ready(self.terminal_io_result())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for LiveStreamReader {
    fn drop(&mut self) {
        if self.terminal.is_none() && !self.worker.is_finished() {
            self.worker
                .abort_with_reason(CancelReason::user("live stream reader dropped"));
        }
        self.output.abort();
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
    fn read(output: &Output, ctx: &mut Context<'_>, count: usize) -> Poll<Vec<u8>> {
        let mut bytes = vec![0; count];
        let mut buffer = ReadBuf::new(&mut bytes);
        output
            .poll_read(ctx, &mut buffer)
            .map(|()| buffer.filled().to_vec())
    }

    #[test]
    fn empty_pipe_parks_without_spinning_and_only_latest_reader_is_woken() {
        let output = Output::new(3);
        let (stale, stale_waker) = counter();
        let (latest, latest_waker) = counter();
        let mut stale_ctx = Context::from_waker(&stale_waker);
        let mut latest_ctx = Context::from_waker(&latest_waker);
        assert!(read(&output, &mut stale_ctx, 2).is_pending());
        for _ in 0..20 {
            assert!(read(&output, &mut latest_ctx, 2).is_pending());
        }
        assert_eq!(latest.0.load(Ordering::SeqCst), 0);
        assert_eq!(ready(output.poll_write(&mut stale_ctx, b"abcde")), 3);
        assert_eq!(stale.0.load(Ordering::SeqCst), 0);
        assert_eq!(latest.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            read(&output, &mut latest_ctx, 2),
            Poll::Ready(b"ab".to_vec())
        );
        assert_eq!(
            read(&output, &mut latest_ctx, 2),
            Poll::Ready(b"c".to_vec())
        );
        assert!(read(&output, &mut latest_ctx, 2).is_pending());
        let state = output.state.lock();
        assert_eq!(
            (state.accepted, state.consumed, state.high_water),
            (3, 3, 3)
        );
    }

    #[test]
    fn epoch_flush_requires_full_consumption_and_never_acknowledges_buffering() {
        let output = Output::new(4);
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(output.poll_write(&mut ctx, b"abcd")), 4);
        assert!(output.poll_write(&mut ctx, b"next").is_pending());
        assert!(output.poll_flush(&mut ctx).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(read(&output, &mut ctx, 3), Poll::Ready(b"abc".to_vec()));
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(output.poll_flush(&mut ctx).is_pending());
        assert_eq!(read(&output, &mut ctx, 3), Poll::Ready(b"d".to_vec()));
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        ready(output.poll_flush(&mut ctx));
    }

    #[test]
    fn producer_drop_keeps_verified_bytes_but_cannot_create_eof() {
        let output = Output::new(4);
        let sink = OutputSink(Arc::clone(&output));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&output, &mut ctx, 4).is_pending());
        drop(sink);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(read(&output, &mut ctx, 4).is_pending());

        let sink = OutputSink(Arc::clone(&output));
        assert_eq!(ready(output.poll_write(&mut ctx, b"safe")), 4);
        drop(sink);
        assert_eq!(read(&output, &mut ctx, 4), Poll::Ready(b"safe".to_vec()));
        assert!(read(&output, &mut ctx, 4).is_pending());
    }

    #[test]
    fn cancellation_discards_unread_bytes_and_wakes_a_parked_epoch_flush() {
        let output = Output::new(4);
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(output.poll_write(&mut ctx, b"data")), 4);
        assert_eq!(read(&output, &mut ctx, 1), Poll::Ready(b"d".to_vec()));
        assert!(output.poll_flush(&mut ctx).is_pending());
        output.abort();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(output.poll_flush(&mut ctx), Poll::Ready(Err(_))));
        assert!(matches!(
            output.poll_write(&mut ctx, b"x"),
            Poll::Ready(Err(_))
        ));
        let state = output.state.lock();
        assert!(state.bytes.is_empty());
        assert_eq!((state.accepted, state.consumed), (4, 1));
        drop(state);
        output.abort();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wraparound_reads_preserve_order_and_the_byte_bound() {
        let output = Output::new(7);
        let waker = Waker::noop();
        let mut ctx = Context::from_waker(waker);
        let input: Vec<u8> = (0..=255).cycle().take(2048).collect();
        let mut sent = 0;
        let mut received = Vec::new();
        while received.len() < input.len() {
            if sent < input.len() {
                if let Poll::Ready(Ok(count)) = output.poll_write(&mut ctx, &input[sent..]) {
                    sent += count;
                }
            }
            if let Poll::Ready(bytes) = read(&output, &mut ctx, 3) {
                received.extend_from_slice(&bytes);
            }
        }
        assert_eq!(received, input);
        assert_eq!(output.state.lock().high_water, 7);
        ready(output.poll_flush(&mut ctx));
    }
}
