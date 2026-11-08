//! Asynchronous handles to the process's standard input, output and error.
//!
//! The standard streams cannot be put in non-blocking mode without changing
//! them for every process that shares them, so each blocking call runs off
//! the async workers: on the runtime's blocking pool, or on a dedicated
//! thread when there is none. A read of standard input can wait
//! indefinitely, and a write can wait on a full pipe, without stalling other
//! tasks. A closed pool or failed thread creation returns an I/O error; a
//! standard-stream syscall never falls back to the async worker. A pending
//! pool read can delay the runtime's bounded blocking-pool shutdown until its
//! timeout, because the OS read itself cannot be interrupted.
//!
//! - [`Stdin`] reads in chunks. A read in flight belongs to the handle, so a
//!   cancelled `read` loses no input as long as the handle is kept: the next
//!   read returns those bytes. Dropping the handle while a read waits leaves
//!   that blocking read running until input arrives, and its bytes are lost;
//!   keep one `Stdin` for the life of the program.
//! - [`Stdout`] and [`Stderr`] write behind: `write` copies the bytes,
//!   starts the blocking write and returns. The next `write`, `flush` or
//!   `shutdown` waits for it and reports its error. Bytes accepted by
//!   `write` are written even if the handle is dropped first; `flush`
//!   before exiting to know they arrived. Admission refusal is reported by
//!   `write` before accepting any bytes, including when a configured pool
//!   queue or the bounded fallback thread capacity is full.
//!
//! Like the other I/O entry points that take no [`Cx`](crate::Cx), the
//! handles consult the calling task's context: a task whose context lacks
//! the IO capability is refused with `[ASUP-E009]`
//! ([`IoCapabilityDenied`](crate::cx::IoCapabilityDenied)).
//!
//! Each handle orders its own operations. Separate handles to one stream do
//! not coordinate, so concurrent writers can interleave chunks, as with
//! separate `std::io::stdout()` handles.
//!
//! ```no_run
//! use asupersync::io::{AsyncWriteExt, BufReader, Lines, stdin, stdout};
//! use asupersync::stream::StreamExt;
//!
//! # async fn echo() -> std::io::Result<()> {
//! let mut lines = Lines::new(BufReader::new(stdin()));
//! let mut out = stdout();
//! while let Some(line) = lines.next().await {
//!     out.write_all(line?.to_uppercase().as_bytes()).await?;
//!     out.write_all(b"\n").await?;
//! }
//! out.flush().await
//! # }
//! ```

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// The most bytes one blocking read or write moves.
const CHUNK_BYTES: usize = 64 * 1024;

type Blocking<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// Runs `op` off the async workers: on the current runtime's blocking pool,
/// or on a dedicated thread outside a runtime or in one built without a pool.
fn off_worker<T, Op>(op: Op) -> Blocking<T>
where
    T: Send + 'static,
    Op: FnOnce() -> io::Result<T> + Send + 'static,
{
    let pool = crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance());
    Box::pin(crate::runtime::spawn_blocking::spawn_blocking_io_off_worker(pool, op))
}

/// An asynchronous handle to the process's standard input; see the
/// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
pub struct Stdin {
    state: ReadState,
}

enum ReadState {
    Idle,
    Reading(Blocking<Vec<u8>>),
    /// Bytes read but not yet handed to a caller.
    Buffered {
        bytes: Vec<u8>,
        consumed: usize,
    },
}

/// An asynchronous handle to the process's standard input.
#[must_use]
pub fn stdin() -> Stdin {
    Stdin {
        state: ReadState::Idle,
    }
}

impl AsyncRead for Stdin {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                ReadState::Buffered { bytes, consumed } => {
                    let available = &bytes[*consumed..];
                    let take = available.len().min(buf.remaining());
                    buf.put_slice(&available[..take]);
                    *consumed += take;
                    if *consumed == bytes.len() {
                        this.state = ReadState::Idle;
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Idle => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    crate::cx::io_gate::require_ambient_io("io::stdin")?;
                    let len = buf.remaining().min(CHUNK_BYTES);
                    this.state = ReadState::Reading(off_worker(move || {
                        let mut bytes = vec![0_u8; len];
                        let read = io::stdin().lock().read(&mut bytes)?;
                        bytes.truncate(read);
                        Ok(bytes)
                    }));
                }
                ReadState::Reading(read) => match read.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        this.state = ReadState::Idle;
                        let bytes = result?;
                        if bytes.is_empty() {
                            // End of input.
                            return Poll::Ready(Ok(()));
                        }
                        this.state = ReadState::Buffered { bytes, consumed: 0 };
                    }
                },
            }
        }
    }
}

impl std::fmt::Debug for Stdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("Stdin { .. }")
    }
}

#[derive(Clone, Copy)]
enum Target {
    Stdout,
    Stderr,
}

impl Target {
    const fn operation(self) -> &'static str {
        match self {
            Self::Stdout => "io::stdout",
            Self::Stderr => "io::stderr",
        }
    }
}

/// The result slot of a write or flush running on the blocking pool.
#[derive(Default)]
struct Completion {
    state: parking_lot::Mutex<(Option<io::Result<()>>, Option<Waker>)>,
    /// The pool's handle for the job, kept only on a byte-bounded pool, where the job's bytes outlive its result: the
    /// job reports its result from inside its closure, before the worker drops the closure and returns the bytes.
    /// Set once, at submission, before anyone polls.
    job: std::sync::OnceLock<crate::runtime::BlockingTaskHandle>,
}

impl Completion {
    fn finish(&self, result: io::Result<()>) {
        let waker = {
            let mut state = self.state.lock();
            state.0 = Some(result);
            state.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn poll(&self, cx: &Context<'_>) -> Poll<io::Result<()>> {
        // Wait for the pool's own "done" first: it is reported after the worker has dropped the job's closure and
        // returned its bytes, so a writer told "done" can start its next operation without finding its own previous
        // bytes still reserved. Then the result is already here (the job stored it before it returned).
        if let Some(job) = self.job.get()
            && job.poll_done(cx).is_pending()
        {
            return Poll::Pending;
        }
        let mut incoming = None;
        loop {
            let mut state = self.state.lock();
            if let Some(result) = state.0.take() {
                let retired = state.1.take();
                drop(state);
                drop(retired);
                drop(incoming);
                return Poll::Ready(result);
            }
            if state
                .1
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                drop(state);
                drop(incoming);
                return Poll::Pending;
            }
            if let Some(incoming) = incoming.take() {
                let retired = state.1.replace(incoming);
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            // A custom clone can reenter or race completion. Recheck the
            // result after preparing the waker outside the mutex.
            drop(state);
            incoming = Some(cx.waker().clone());
        }
    }

    fn clear_waiter(&self) {
        let retired = self.state.lock().1.take();
        drop(retired);
        if let Some(job) = self.job.get() {
            job.clear_done_waiter();
        }
    }
}

/// Finishes a [`Completion`] with an error when the pool drops its job
/// without running it (the pool is shutting down) or the job panics.
struct Unfinished(Option<Arc<Completion>>);

impl Drop for Unfinished {
    fn drop(&mut self) {
        if let Some(completion) = self.0.take() {
            completion.finish(Err(io::Error::other(
                "the standard stream operation did not complete: the blocking pool \
                 refused it or it panicked",
            )));
        }
    }
}

/// The closure a blocking pool runs for `op`: it runs `op` and reports the result to `unfinished`'s completion.
/// The one place it is built, for a real submission and for measuring one.
fn pool_job<Op>(op: Op, mut unfinished: Unfinished) -> impl FnOnce() + Send + 'static
where
    Op: FnOnce() -> io::Result<()> + Send + 'static,
{
    move || {
        let result = op();
        if let Some(completion) = unfinished.0.take() {
            completion.finish(result);
        }
    }
}

/// The operation that writes `chunk` to `target`. The one place it is built, for a real write and for measuring one.
fn write_job(target: Target, chunk: Vec<u8>) -> impl FnOnce() -> io::Result<()> + Send + 'static {
    move || match target {
        Target::Stdout => io::stdout().lock().write_all(&chunk),
        Target::Stderr => io::stderr().lock().write_all(&chunk),
    }
}

#[cfg(test)]
thread_local! {
    /// How many times `copy_chunk` ran on this thread: a write copies its input on the thread that polls it.
    static CHUNK_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The one place a write copies its borrowed input into the heap its job will own. It runs only inside the pool's
/// factory, after the reservation, and (on the thread fallback) when there is no pool to reserve from.
fn copy_chunk(input: &[u8]) -> Vec<u8> {
    #[cfg(test)]
    CHUNK_COPIES.with(|copies| copies.set(copies.get() + 1));
    input.to_vec()
}

/// The bytes a byte-bounded pool measures for a write's job, whatever the payload length: the size of the very closure
/// a write submits, built by the same two functions with an empty payload (an empty `Vec` owns no heap).
fn write_job_storage(target: Target) -> usize {
    std::mem::size_of_val(&pool_job(write_job(target, Vec::new()), Unfinished(None)))
}

/// The most payload bytes one write may copy and declare: [`CHUNK_BYTES`], or on a byte-bounded pool the pool's limit
/// less the measured storage of the write's job and less the bytes the pool has pinned for good, so that a short write
/// fits exactly. An error when not even one payload byte can be admitted, which no waiting changes, and never a zero
/// limit (`Ok(0)` for a non-empty write would make `write_all` fail or spin):
///
/// * `InvalidInput` when the pool's original limit cannot hold the write job's storage plus one byte. No write was
///   ever possible there, and the configuration is the caller's to fix.
/// * `Other` when the original limit could hold a write but the reservations pinned for good (see
///   [`crate::runtime::BlockingPool::quarantined_bytes`]) have taken the room. That is a fault of the pool, not an
///   invalid request.
fn write_payload_limit(target: Target) -> io::Result<usize> {
    let Some(pool) =
        crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance())
    else {
        return Ok(CHUNK_BYTES);
    };
    let crate::runtime::BlockingAdmissionPolicy::BoundedBytes { max_live_bytes, .. } =
        pool.admission_policy()
    else {
        return Ok(CHUNK_BYTES);
    };
    let original = max_live_bytes
        .get()
        .checked_sub(write_job_storage(target))
        .filter(|room| *room > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the blocking pool's byte limit cannot hold a standard stream write",
            )
        })?;
    let room = original.saturating_sub(pool.quarantined_bytes());
    if room == 0 {
        return Err(io::Error::other(
            "the blocking pool has pinned too many bytes for good (a panic payload could not be \
             destroyed) to take a standard stream write",
        ));
    }
    Ok(room.min(CHUNK_BYTES))
}

/// A write or flush in flight. It starts when it is created, and dropping it
/// does not cancel it, so bytes accepted by `write` are written even if the
/// handle is dropped first (br-asupersync-68jvck).
enum InFlight {
    /// On the runtime's blocking pool, which runs it whether or not anyone
    /// waits for the result.
    Pool(Arc<Completion>),
    /// On a dedicated thread, outside a runtime or in one without a pool.
    /// The thread has already started before this state is published.
    Thread(Blocking<()>),
}

impl InFlight {
    /// Starts an operation whose captures own no heap. For the tests, which build such operations.
    #[cfg(test)]
    fn start<Op>(op: Op) -> io::Result<Self>
    where
        Op: FnOnce() -> io::Result<()> + Send + 'static,
    {
        Self::start_charged(op, 0)
    }

    /// Starts `op`, whose captures own `declared_heap_bytes` of heap behind their pointers (the payload of a
    /// write, 0 for a flush).
    ///
    /// A pool that bounds live job bytes measures the closure's own storage, adds the declared heap, reserves both
    /// when it admits the job and returns them after the closure and its allocation have been dropped; any other
    /// pool ignores the declaration. A refusal (including a pool with no room) reaches the caller as an error
    /// before the operation is accepted, so a refused write was never accepted and nothing is run inline.
    fn start_charged<Op>(op: Op, declared_heap_bytes: usize) -> io::Result<Self>
    where
        Op: FnOnce() -> io::Result<()> + Send + 'static,
    {
        Self::start_charged_with(move || op, declared_heap_bytes)
    }

    /// [`Self::start_charged`] for an operation that owns heap it has not yet allocated: `make_op` builds it, and on a
    /// pool it runs only AFTER the pool has reserved the operation's closure storage, `declared_heap_bytes` and a queue
    /// slot. A refusal is therefore decided before any payload exists, and `make_op` (which may borrow the caller's
    /// input) is not called. Nothing parks: a pool with no room is an error at once.
    fn start_charged_with<Make, Op>(make_op: Make, declared_heap_bytes: usize) -> io::Result<Self>
    where
        Make: FnOnce() -> Op,
        Op: FnOnce() -> io::Result<()> + Send + 'static,
    {
        if let Some(pool) =
            crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance())
        {
            let completion = Arc::new(Completion::default());
            let unfinished = Unfinished(Some(Arc::clone(&completion)));
            // The handle is kept only on a byte-bounded pool (below). Dropping it never cancels the job.
            let job = pool.try_spawn_charged_with(declared_heap_bytes, move || {
                pool_job(make_op(), unfinished)
            });
            let handle = match job {
                Ok(handle) => handle,
                Err(crate::runtime::BlockingFactoryError::Refused(refused)) => {
                    let kind = match refused.kind() {
                        crate::runtime::BlockingSpawnErrorKind::Saturated
                        | crate::runtime::BlockingSpawnErrorKind::ByteBudgetSaturated => {
                            io::ErrorKind::WouldBlock
                        }
                        crate::runtime::BlockingSpawnErrorKind::Shutdown
                        | crate::runtime::BlockingSpawnErrorKind::ByteBudgetQuarantined => {
                            io::ErrorKind::Other
                        }
                        crate::runtime::BlockingSpawnErrorKind::Forbidden => {
                            io::ErrorKind::Unsupported
                        }
                        crate::runtime::BlockingSpawnErrorKind::ChargeRequired
                        | crate::runtime::BlockingSpawnErrorKind::ChargeTooLarge => {
                            io::ErrorKind::InvalidInput
                        }
                    };
                    drop(refused);
                    return Err(io::Error::new(
                        kind,
                        "the blocking pool refused the standard stream operation",
                    ));
                }
                Err(crate::runtime::BlockingFactoryError::FactoryPanicked { .. }) => {
                    return Err(io::Error::other(
                        "the standard stream operation's payload factory panicked",
                    ));
                }
                Err(crate::runtime::BlockingFactoryError::Shutdown { .. }) => {
                    return Err(io::Error::other(
                        "the blocking pool closed before the standard stream operation was queued",
                    ));
                }
            };
            // Only on a byte-bounded pool does the job's reservation outlive its reported result, so only there is the
            // writer made to wait for the pool's own "done"; every other policy settles on the result alone, as before.
            if matches!(
                pool.admission_policy(),
                crate::runtime::BlockingAdmissionPolicy::BoundedBytes { .. }
            ) {
                let _ = completion.job.set(handle);
            }
            return Ok(Self::Pool(completion));
        }
        let thread = crate::runtime::spawn_blocking::try_spawn_blocking_io_on_thread(make_op())?;
        Ok(Self::Thread(Box::pin(thread)))
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Pool(completion) => completion.poll(cx),
            Self::Thread(thread) => thread.as_mut().poll(cx),
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Self::Pool(completion) = self {
            // The committed write continues, but an abandoned wait must not
            // keep its caller alive through a blocked pool operation.
            completion.clear_waiter();
        }
    }
}

/// Write-behind state shared by [`Stdout`] and [`Stderr`].
struct Writer {
    target: Target,
    state: WriteState,
}

enum WriteState {
    Idle,
    Writing(InFlight),
    Flushing(InFlight),
}

impl Writer {
    const fn new(target: Target) -> Self {
        Self {
            target,
            state: WriteState::Idle,
        }
    }

    /// Waits for the operation in flight, if any, and returns its result.
    fn poll_settle(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let operation = match &mut self.state {
            WriteState::Idle => return Poll::Ready(Ok(())),
            WriteState::Writing(operation) | WriteState::Flushing(operation) => operation,
        };
        let result = std::task::ready!(operation.poll(cx));
        self.state = WriteState::Idle;
        Poll::Ready(result)
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        std::task::ready!(self.poll_settle(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let target = self.target;
        crate::cx::io_gate::require_ambient_io(target.operation())?;
        // On a byte-bounded pool the payload is clamped to what the pool could admit beside the write job's own storage
        // (an ordinary short write). If not even one byte fits, say so now, with the reason: `Ok(0)` for a non-empty
        // write would make `write_all` fail with `WriteZero` or spin.
        let limit = write_payload_limit(target)?;
        let written = data.len().min(limit);
        let input = &data[..written];
        // The copied payload is the heap the closure owns (`to_vec` allocates exactly `len`), so that is what is
        // declared. The closure's own storage is measured by the pool, and `write_payload_limit` measured the same
        // closure. The copy is made inside the factory, so only after the pool has reserved both and a queue slot: a
        // pool that cannot hold the write refuses it before any byte is copied or accepted.
        self.state = WriteState::Writing(InFlight::start_charged_with(
            || write_job(target, copy_chunk(input)),
            written,
        )?);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                WriteState::Flushing(_) => return self.poll_settle(cx),
                WriteState::Writing(_) => std::task::ready!(self.poll_settle(cx))?,
                WriteState::Idle => {
                    let target = self.target;
                    crate::cx::io_gate::require_ambient_io(target.operation())?;
                    // The flush closure captures only the stream selector: no heap, so it declares 0.
                    self.state = WriteState::Flushing(InFlight::start_charged(
                        move || match target {
                            Target::Stdout => io::stdout().lock().flush(),
                            Target::Stderr => io::stderr().lock().flush(),
                        },
                        0,
                    )?);
                }
            }
        }
    }
}

macro_rules! output_handle {
    ($(#[$attr:meta])* $name:ident, $constructor:ident, $target:expr, $stream:literal) => {
        $(#[$attr])*
        pub struct $name {
            writer: Writer,
        }

        #[doc = concat!("An asynchronous handle to the process's standard ", $stream, ".")]
        #[must_use]
        pub fn $constructor() -> $name {
            $name {
                writer: Writer::new($target),
            }
        }

        impl AsyncWrite for $name {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.get_mut().writer.poll_write(cx, data)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.get_mut().writer.poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.get_mut().writer.poll_flush(cx)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.pad(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

output_handle!(
    /// An asynchronous handle to the process's standard output; see the
    /// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
    Stdout,
    stdout,
    Target::Stdout,
    "output"
);

output_handle!(
    /// An asynchronous handle to the process's standard error; see the
    /// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
    Stderr,
    stderr,
    Target::Stderr,
    "error"
);

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::Cx;
    use crate::io::AsyncReadExt;
    use crate::runtime::{
        BlockingAdmissionPolicy, BlockingPool, BlockingPoolOptions, BlockingQueuePolicy,
    };
    use futures_lite::future;
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Weak, mpsc};
    use std::task::Wake;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn standard_stream_io_runs_off_worker_with_and_without_a_pool() {
        let pool = BlockingPool::new(1, 1);
        for context in [
            None,
            Some(Cx::for_testing()),
            Some(Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()))),
        ] {
            let _ambient = Cx::set_current(context);
            let polling_thread = std::thread::current().id();
            let worker = future::block_on(off_worker(|| Ok(std::thread::current().id())))
                .expect("off-worker I/O result");
            assert_ne!(worker, polling_thread);
            let error = future::block_on(off_worker(|| {
                Err::<(), _>(io::Error::new(io::ErrorKind::NotFound, "I/O sentinel"))
            }))
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
        }
        assert!(pool.shutdown_and_wait(WAIT));
    }

    #[test]
    fn standard_stream_io_never_runs_inline_after_pool_shutdown() {
        let pool = BlockingPool::new(1, 1);
        let context = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
        assert!(pool.shutdown_and_wait(WAIT));
        let _ambient = Cx::set_current(Some(context));
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        // This is the same bridge Stdin polls. A closed pool used to invoke
        // the closure here, potentially waiting for input on the async worker.
        let error = future::block_on(off_worker(move || {
            called.fetch_add(1, Ordering::SeqCst);
            Ok(23)
        }))
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let mut poll = Context::from_waker(Waker::noop());
        for target in [Target::Stdout, Target::Stderr] {
            let mut writer = Writer::new(target);
            assert!(matches!(
                writer.poll_write(&mut poll, b"refused before acceptance"),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(writer.state, WriteState::Idle));
            assert!(matches!(writer.poll_flush(&mut poll), Poll::Ready(Err(_))));
        }
    }

    #[test]
    fn saturated_pool_writes_refuse_bytes_before_accepting_them() {
        let pool = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions::default(),
            BlockingQueuePolicy::Fifo,
            BlockingAdmissionPolicy::Bounded {
                max_queued: NonZeroUsize::new(1).unwrap(),
            },
        );
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let running = pool
            .try_spawn(move || {
                entered.send(()).unwrap();
                gate.recv_timeout(WAIT).unwrap();
            })
            .unwrap();
        entry.recv_timeout(WAIT).unwrap();
        let queued = pool.try_spawn(|| {}).unwrap();
        assert_eq!(pool.pending_count(), 1);
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut poll = Context::from_waker(Waker::noop());
        for target in [Target::Stdout, Target::Stderr] {
            let mut writer = Writer::new(target);
            assert!(matches!(
                writer.poll_write(&mut poll, b"must never reach the stream"),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock
            ));
            assert!(matches!(writer.state, WriteState::Idle));
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        assert!(
            InFlight::start(move || {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    fn byte_pool(max_queued: usize, max_live_bytes: usize) -> BlockingPool {
        BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions::default(),
            BlockingQueuePolicy::Fifo,
            BlockingAdmissionPolicy::BoundedBytes {
                max_queued: NonZeroUsize::new(max_queued).unwrap(),
                max_live_bytes: NonZeroUsize::new(max_live_bytes).unwrap(),
            },
        )
    }

    #[test]
    fn a_byte_bounded_pool_refuses_a_write_that_does_not_fit_and_still_takes_a_zero_heap_flush() {
        let pool = byte_pool(2, 1024);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let running = pool
            .try_spawn_charged(
                move || {
                    entered.send(()).unwrap();
                    gate.recv_timeout(WAIT).unwrap();
                },
                800,
            )
            .unwrap();
        entry.recv_timeout(WAIT).unwrap();
        let held = pool.charged_bytes();
        let held_storage = pool.charged_storage_bytes();
        assert_eq!(pool.charged_declared_bytes(), 800);
        let room = 1024 - held;
        assert!(
            room >= 64,
            "the holder's own storage is a few dozen bytes: {room}"
        );
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut writer = Writer::new(Target::Stdout);
        let mut poll = Context::from_waker(Waker::noop());

        // A payload of exactly the room left declares `room` bytes, and the write's own closure adds storage the pool
        // measures: together they do not fit beside the running job, so the write is refused before any byte is
        // accepted, nothing reaches the stream, and nothing stays reserved.
        assert!(matches!(
            writer.poll_write(&mut poll, &vec![b'x'; room]),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert!(matches!(writer.state, WriteState::Idle));
        assert_eq!(pool.charged_bytes(), held);

        // The permitted counterpart: a flush declares no heap. Its closure storage is measured all the same, and it
        // is admitted beside the running job.
        assert!(writer.poll_flush(&mut poll).is_pending());
        assert!(matches!(writer.state, WriteState::Flushing(_)));
        assert_eq!(pool.charged_declared_bytes(), 800);
        assert!(pool.charged_storage_bytes() > held_storage);
        release.send(()).unwrap();
        future::block_on(future::poll_fn(|cx| writer.poll_flush(cx))).expect("the flush completes");
        assert!(running.wait_timeout(WAIT));
        // The flush reports completion from inside its closure; its bytes are returned a moment later, after the
        // closure and its allocation are gone. Shutdown waits for the worker to finish that.
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
    }

    #[test]
    fn a_byte_bounded_pool_takes_a_short_write_of_the_room_beyond_the_jobs_measured_storage() {
        let fixed = write_job_storage(Target::Stdout);
        let spaces = [b' '; 10];
        let mut poll = Context::from_waker(Waker::noop());

        // A limit equal to the write job's own storage leaves no room for a payload byte: a typed refusal at once,
        // never `Ok(0)` for a non-empty write, and nothing accepted or reserved.
        let none = byte_pool(2, fixed);
        {
            let _ambient = Cx::set_current(Some(
                Cx::for_testing().with_blocking_pool_handle(Some(none.handle())),
            ));
            let mut writer = Writer::new(Target::Stdout);
            assert!(matches!(
                writer.poll_write(&mut poll, &spaces),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput
            ));
            assert!(matches!(writer.state, WriteState::Idle));
        }
        assert_eq!(none.charged_bytes(), 0);
        assert!(none.shutdown_and_wait(WAIT));

        // The permitted counterpart: five bytes of room beyond that storage take exactly five bytes of a longer
        // write (an ordinary short write); the other five are the caller's to write next.
        let five = byte_pool(2, fixed + 5);
        {
            let _ambient = Cx::set_current(Some(
                Cx::for_testing().with_blocking_pool_handle(Some(five.handle())),
            ));
            let mut writer = Writer::new(Target::Stdout);
            assert!(matches!(
                writer.poll_write(&mut poll, &spaces),
                Poll::Ready(Ok(5))
            ));
            future::block_on(future::poll_fn(|cx| writer.poll_settle(cx)))
                .expect("the short write completes");
        }
        assert!(five.shutdown_and_wait(WAIT));
        assert_eq!(five.charged_bytes(), 0);
    }

    /// A payload whose destructor panics: the pool cannot tell what it kept alive, so it pins the job's reservation.
    struct PanicsWhenDropped;

    impl Drop for PanicsWhenDropped {
        fn drop(&mut self) {
            std::panic::resume_unwind(Box::new(0_u8));
        }
    }

    /// Pins `bytes` of `pool` for good, the way a job whose panic payload cannot be destroyed does.
    fn pin_bytes(pool: &BlockingPool, bytes: usize) {
        let before = pool.quarantined_bytes();
        let task = pool
            .try_spawn_charged(
                || {
                    std::panic::resume_unwind(Box::new(PanicsWhenDropped));
                },
                bytes,
            )
            .unwrap();
        assert!(task.wait_timeout(WAIT));
        assert_eq!(pool.quarantined_bytes(), before + bytes);
    }

    #[test]
    fn pinned_bytes_shrink_the_write_clamp_and_a_write_with_no_room_left_is_a_pool_fault() {
        let fixed = write_job_storage(Target::Stdout);
        let spaces = [b' '; 10];
        let mut poll = Context::from_waker(Waker::noop());
        let pool = byte_pool(2, fixed + 8);
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut writer = Writer::new(Target::Stdout);

        // Three pinned bytes leave room for a five-byte payload: a longer write is clamped to what still fits and
        // completes, instead of being refused for good against the pool's original limit.
        pin_bytes(&pool, 3);
        assert!(matches!(
            writer.poll_write(&mut poll, &spaces),
            Poll::Ready(Ok(5))
        ));
        future::block_on(future::poll_fn(|cx| writer.poll_settle(cx)))
            .expect("the short write completes");

        // Five more leave room for the job's own storage and no payload byte. The pool's original limit could hold a
        // write, so this is not an invalid request but a pool that lost its room: `Other`, with the reason, at once,
        // never `Ok(0)` and never `WouldBlock`, which would invite a retry that cannot succeed.
        pin_bytes(&pool, 5);
        assert!(matches!(
            writer.poll_write(&mut poll, &spaces),
            Poll::Ready(Err(error))
                if error.kind() == io::ErrorKind::Other && error.to_string().contains("pinned")
        ));
        assert!(matches!(writer.state, WriteState::Idle));
        assert_eq!(pool.charged_bytes(), 8);
        assert!(pool.shutdown_and_wait(WAIT));
    }

    #[test]
    fn a_pool_whose_original_limit_never_held_a_write_stays_invalid_input_with_bytes_pinned() {
        // The classification follows the original limit, not the pin: one that never could hold a write is the
        // caller's configuration to fix.
        let fixed = write_job_storage(Target::Stdout);
        let mut poll = Context::from_waker(Waker::noop());
        let tiny = byte_pool(2, fixed);
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(tiny.handle())),
        ));
        let mut writer = Writer::new(Target::Stdout);
        pin_bytes(&tiny, 1);
        assert!(matches!(
            writer.poll_write(&mut poll, b"x"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(matches!(writer.state, WriteState::Idle));
        assert!(tiny.shutdown_and_wait(WAIT));
    }

    #[test]
    fn a_flush_that_no_longer_fits_beside_pinned_bytes_is_refused_for_good_not_told_to_wait() {
        let fixed = write_job_storage(Target::Stdout);
        let mut poll = Context::from_waker(Waker::noop());
        let pool = byte_pool(2, fixed + 8);
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut writer = Writer::new(Target::Stdout);

        // Permitted: with nothing pinned the flush is admitted and completes.
        future::block_on(future::poll_fn(|cx| writer.poll_flush(cx))).expect("the flush completes");

        // One byte of room is left, less than the flush job's own storage: refused for good, as for a shutdown pool,
        // and not as `WouldBlock`.
        pin_bytes(&pool, fixed + 7);
        assert!(matches!(
            writer.poll_flush(&mut poll),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Other
        ));
        assert!(matches!(writer.state, WriteState::Idle));
        assert!(pool.shutdown_and_wait(WAIT));
    }

    /// How many times the real `copy_chunk` has run on this thread: a write copies its input on the thread that polls it.
    fn copies() -> usize {
        CHUNK_COPIES.with(std::cell::Cell::get)
    }

    #[test]
    fn a_write_copies_its_input_only_after_the_pool_has_reserved_room_for_it() {
        let fixed = write_job_storage(Target::Stderr);
        let spaces = [b' '; 10];
        let mut poll = Context::from_waker(Waker::noop());

        // The queue is full: the worker is busy and one job waits. The write is refused, and nothing was copied.
        {
            let pool = byte_pool(1, 4096);
            let _ambient = Cx::set_current(Some(
                Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
            ));
            let mut writer = Writer::new(Target::Stderr);
            let (entered, entry) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let running = pool
                .try_spawn_charged(
                    move || {
                        entered.send(()).unwrap();
                        gate.recv_timeout(WAIT).unwrap();
                    },
                    0,
                )
                .unwrap();
            entry.recv_timeout(WAIT).unwrap();
            let queued = pool.try_spawn_charged(|| {}, 0).unwrap();
            let before = copies();
            assert!(matches!(
                writer.poll_write(&mut poll, &spaces),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock
            ));
            assert_eq!(copies(), before, "the input was copied for a full queue");
            assert!(matches!(writer.state, WriteState::Idle));
            release.send(()).unwrap();
            assert!(running.wait_timeout(WAIT) && queued.wait_timeout(WAIT));

            // The permitted counterpart: with room, the same write is accepted, copied exactly once, and completes.
            assert!(matches!(
                writer.poll_write(&mut poll, &spaces),
                Poll::Ready(Ok(10))
            ));
            assert_eq!(copies(), before + 1);
            future::block_on(future::poll_fn(|cx| writer.poll_settle(cx)))
                .expect("the write completes");
            assert_eq!(pool.charged_bytes(), 0);
            assert!(pool.shutdown_and_wait(WAIT));
        }

        // The bytes are full: a running job leaves no room for the largest write the limit allows.
        {
            let pool = byte_pool(4, fixed + 8);
            let _ambient = Cx::set_current(Some(
                Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
            ));
            let mut writer = Writer::new(Target::Stderr);
            let (entered, entry) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let running = pool
                .try_spawn_charged(
                    move || {
                        entered.send(()).unwrap();
                        gate.recv_timeout(WAIT).unwrap();
                    },
                    1,
                )
                .unwrap();
            entry.recv_timeout(WAIT).unwrap();
            let before = copies();
            assert!(matches!(
                writer.poll_write(&mut poll, &spaces),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock
            ));
            assert_eq!(copies(), before, "the input was copied for a full pool");
            release.send(()).unwrap();
            assert!(running.wait_timeout(WAIT));

            // Permitted: once the running job is gone, the clamped write (8 bytes of the 10) is copied once and runs.
            assert!(matches!(
                writer.poll_write(&mut poll, &spaces),
                Poll::Ready(Ok(8))
            ));
            assert_eq!(copies(), before + 1);
            future::block_on(future::poll_fn(|cx| writer.poll_settle(cx)))
                .expect("the clamped write completes");
            assert_eq!(pool.charged_bytes(), 0);
            assert!(pool.shutdown_and_wait(WAIT));
        }
    }

    #[test]
    fn the_write_storage_the_clamp_measures_is_what_the_pool_charges() {
        let pool = byte_pool(2, 1 << 20);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let holder = move || {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        };
        let holder_storage = std::mem::size_of_val(&holder);
        let running = pool.try_spawn_charged(holder, 100).unwrap();
        entry.recv_timeout(WAIT).unwrap();
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut writer = Writer::new(Target::Stdout);
        let mut poll = Context::from_waker(Waker::noop());
        // Three payload bytes queue behind the holder. The pool's measured storage is the holder's plus exactly what
        // the clamp measured for the write, and its declared heap is the holder's plus exactly the payload.
        assert!(matches!(
            writer.poll_write(&mut poll, b"   "),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(
            pool.charged_storage_bytes(),
            holder_storage + write_job_storage(Target::Stdout)
        );
        assert_eq!(pool.charged_declared_bytes(), 100 + 3);
        release.send(()).unwrap();
        future::block_on(future::poll_fn(|cx| writer.poll_settle(cx)))
            .expect("the write completes");
        assert!(running.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
    }

    #[test]
    fn pools_that_do_not_bound_bytes_keep_the_full_write_chunk() {
        let unbounded = BlockingPool::new(1, 1);
        let counted = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions::default(),
            BlockingQueuePolicy::Fifo,
            BlockingAdmissionPolicy::Bounded {
                max_queued: NonZeroUsize::new(2).unwrap(),
            },
        );
        let roomy = byte_pool(2, 1 << 20);
        for pool in [None, Some(&unbounded), Some(&counted), Some(&roomy)] {
            let _ambient = Cx::set_current(Some(
                Cx::for_testing().with_blocking_pool_handle(pool.map(BlockingPool::handle)),
            ));
            assert_eq!(write_payload_limit(Target::Stdout).ok(), Some(CHUNK_BYTES));
            assert_eq!(write_payload_limit(Target::Stderr).ok(), Some(CHUNK_BYTES));
        }
        assert!(unbounded.shutdown_and_wait(WAIT));
        assert!(counted.shutdown_and_wait(WAIT));
        assert!(roomy.shutdown_and_wait(WAIT));
    }

    /// Woken when the pool reports the writer's job done. Records the bytes the pool still has reserved at that instant,
    /// then, if it was given a gate, parks the waking thread until the test lets it go.
    struct Retired {
        pool: crate::runtime::BlockingPoolHandle,
        observed: AtomicUsize,
        woke: std::sync::Mutex<mpsc::Sender<()>>,
        hold: Option<std::sync::Mutex<mpsc::Receiver<()>>>,
    }

    impl Wake for Retired {
        fn wake(self: Arc<Self>) {
            self.observed
                .store(self.pool.charged_bytes(), Ordering::SeqCst);
            let _ = self.woke.lock().unwrap().send(());
            if let Some(hold) = &self.hold {
                let _ = hold.lock().unwrap().recv_timeout(WAIT);
            }
        }
    }

    /// A one-write pool (`fixed + 5` bytes) whose only worker runs a gated job for the writer; when the gate opens the
    /// writer is woken. Returns the bytes still reserved when it was woken and the result of its next `poll_write`
    /// of two bytes. With `park_the_waker` the waking thread stays parked until the result is in, so the poll happens
    /// while the waking thread is exactly where the pool woke it from.
    fn next_chunk_after_the_job_reports_done(
        park_the_waker: bool,
    ) -> (usize, Result<usize, io::ErrorKind>) {
        let fixed = write_job_storage(Target::Stderr);
        let pool = byte_pool(4, fixed + 5);
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let (open, gate) = mpsc::channel();
        let gated = move || {
            gate.recv_timeout(WAIT).unwrap();
            Ok::<(), io::Error>(())
        };
        let flight = InFlight::start(gated).expect("the pool admits the gated job");
        let held = pool.charged_bytes();
        // The gated job fits, and a two-byte write job cannot fit beside it.
        assert!(3 < held && held <= fixed + 5, "{held} vs {fixed}");
        let mut writer = Writer::new(Target::Stderr);
        writer.state = WriteState::Writing(flight);

        let (woke_tx, woke_rx) = mpsc::channel();
        let (release, hold) = mpsc::channel();
        let retired = Arc::new(Retired {
            pool: pool.handle(),
            observed: AtomicUsize::new(usize::MAX),
            woke: std::sync::Mutex::new(woke_tx),
            hold: park_the_waker.then(|| std::sync::Mutex::new(hold)),
        });
        let waker = Waker::from(Arc::clone(&retired));
        let mut cx = Context::from_waker(&waker);
        assert!(writer.poll_settle(&mut cx).is_pending());
        open.send(()).unwrap();
        woke_rx
            .recv_timeout(WAIT)
            .expect("the writer is woken when its job reports done");
        if !park_the_waker {
            // Control: let the job retire completely first. Any later job on the one-worker pool completes only after
            // the first one's closure is gone and its bytes are back.
            let barrier = pool.try_spawn_charged(|| {}, 0).unwrap();
            assert!(barrier.wait_timeout(WAIT));
        }
        let outcome = match writer.poll_write(&mut cx, b"  ") {
            Poll::Ready(Ok(written)) => Ok(written),
            Poll::Ready(Err(error)) => Err(error.kind()),
            Poll::Pending => panic!("the next chunk is neither accepted nor refused"),
        };
        // Let a parked waking thread go before anything can fail, so a failure cannot hang the pool.
        let _ = release.send(());
        if outcome.is_ok() {
            future::block_on(future::poll_fn(|cx| writer.poll_settle(cx)))
                .expect("the accepted chunk completes");
        }
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
        (retired.observed.load(Ordering::SeqCst), outcome)
    }

    #[test]
    fn a_writer_told_its_job_is_done_finds_the_jobs_bytes_back_and_can_start_the_next_chunk() {
        // Red before the repair: the writer is woken from inside the job's closure, while the closure and its bytes
        // are alive, and its next chunk is refused as `WouldBlock` by its own just-finished job. Green after: it is
        // woken from the pool's `done`, which follows the closure's drop and the return of the bytes.
        let (observed, outcome) = next_chunk_after_the_job_reports_done(true);
        assert_eq!(
            observed, 0,
            "woken while its job's bytes were still reserved"
        );
        assert_eq!(outcome, Ok(2));
    }

    #[test]
    fn the_next_chunk_is_admitted_once_the_previous_job_has_fully_retired() {
        // The control: with the previous job already retired, the next chunk is admitted. This is why the refusal above
        // is the retirement window and not the size of the pool.
        let (_observed, outcome) = next_chunk_after_the_job_reports_done(false);
        assert_eq!(outcome, Ok(2));
    }

    #[test]
    fn a_serialized_multi_chunk_write_all_and_flush_complete_on_a_pool_that_holds_one_write_job() {
        let fixed = write_job_storage(Target::Stderr);
        let pool = byte_pool(4, fixed + 5);
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut writer = Writer::new(Target::Stderr);
        let data = [b' '; 12];
        let mut rest: &[u8] = &data;
        let mut chunks = Vec::new();
        future::block_on(future::poll_fn(|cx| {
            while !rest.is_empty() {
                match writer.poll_write(cx, rest) {
                    Poll::Ready(Ok(written)) => {
                        chunks.push(written);
                        rest = &rest[written..];
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            writer.poll_flush(cx)
        }))
        .expect("a serialized write_all and flush complete");
        assert_eq!(chunks, [5, 5, 2]);
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
    }

    /// A waker whose clones can be counted through the `Arc` that backs it, and which records every wake. It is not a
    /// no-op waker: `Waker::noop()` has no `Arc` to count, and a wait that is abandoned must be dropped, never woken.
    struct Counted {
        woken: AtomicUsize,
    }

    impl Wake for Counted {
        fn wake(self: Arc<Self>) {
            self.woken.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn an_accepted_write_survives_dropping_the_writer_and_the_wait_leaves_no_waker_behind() {
        let pool = byte_pool(4, 1 << 20);
        let (open, gate) = mpsc::channel();
        let holder = pool
            .try_spawn_charged(
                move || {
                    gate.recv_timeout(WAIT).unwrap();
                },
                0,
            )
            .unwrap();
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut writer = Writer::new(Target::Stderr);
        let mut poll = Context::from_waker(Waker::noop());
        // Three bytes are accepted: the pool admitted the job, which is queued behind the gated holder.
        assert!(matches!(
            writer.poll_write(&mut poll, b"   "),
            Poll::Ready(Ok(3))
        ));
        let completion = match &writer.state {
            WriteState::Writing(InFlight::Pool(completion)) => Arc::clone(completion),
            _ => panic!("the accepted write is in flight on the pool"),
        };
        // Wait for it with a waker that can be counted.
        let backing = Arc::new(Counted {
            woken: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&backing));
        let mut counted = Context::from_waker(&waker);
        assert!(writer.poll_settle(&mut counted).is_pending());
        // The test's `backing` and `waker`, and the clone the pool registered.
        assert_eq!(Arc::strong_count(&backing), 3);
        // Abandon the wait: the writer goes away and takes the registered waker with it, and the accepted bytes are
        // still written.
        drop(writer);
        drop(waker);
        assert_eq!(
            Arc::strong_count(&backing),
            1,
            "an abandoned wait keeps nothing alive"
        );
        open.send(()).unwrap();
        future::block_on(future::poll_fn(|cx| completion.poll(cx)))
            .expect("the accepted write completed although nobody waited for it");
        assert!(holder.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
        // The abandoned wait's waker was dropped with the writer and never woken, even after its job finished.
        assert_eq!(backing.woken.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancelled_read_wait_preserves_the_handles_in_flight_bytes() {
        for with_pool in [false, true] {
            let pool = BlockingPool::new(1, 1);
            let context =
                Cx::for_testing().with_blocking_pool_handle(with_pool.then(|| pool.handle()));
            let _ambient = Cx::set_current(Some(context));
            let (entered, entry) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let mut input = Stdin {
                state: ReadState::Reading(off_worker(move || {
                    entered.send(()).unwrap();
                    gate.recv_timeout(WAIT).unwrap();
                    Ok(b"abcdef".to_vec())
                })),
            };
            let mut first = [0; 3];
            {
                let mut read = Box::pin(input.read(&mut first));
                assert!(
                    read.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                entry.recv_timeout(WAIT).unwrap();
                // Drop only this borrowing read, retaining Stdin's operation.
            }
            release.send(()).unwrap();
            future::block_on(input.read_exact(&mut first)).unwrap();
            let mut rest = [0; 3];
            future::block_on(input.read_exact(&mut rest)).unwrap();
            assert_eq!(&first, b"abc");
            assert_eq!(&rest, b"def");
            assert!(pool.shutdown_and_wait(WAIT));
        }
    }

    #[test]
    fn accepted_thread_write_runs_even_when_its_unpolled_handle_is_dropped() {
        let _ambient = Cx::set_current(None);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let (finished, finish) = mpsc::channel();
        let operation = InFlight::start(move || {
            entered.send(std::thread::current().id()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
            finished.send(()).unwrap();
            Ok(())
        })
        .unwrap_or_else(|error| panic!("start committed write: {error}"));
        let worker = entry.recv_timeout(WAIT).unwrap();
        assert_ne!(worker, std::thread::current().id());
        // The I/O thread already owns the work. No future poll is necessary
        // for acceptance, and abandonment parks its handle instead of detaching.
        drop(operation);
        assert_eq!(
            crate::runtime::spawn_blocking::parked_thread(worker),
            Some(false)
        );
        release.send(()).unwrap();
        finish.recv_timeout(WAIT).unwrap();
    }

    #[test]
    fn accepted_pool_write_survives_drop_while_still_queued() {
        let pool = BlockingPool::new(1, 1);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let running = pool.spawn(move || {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        });
        entry.recv_timeout(WAIT).unwrap();
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let (finished, finish) = mpsc::channel();
        let operation = InFlight::start(move || {
            finished.send(()).unwrap();
            Ok(())
        })
        .unwrap_or_else(|error| panic!("queue committed write: {error}"));
        assert_eq!(pool.pending_count(), 1);
        drop(operation);
        release.send(()).unwrap();
        finish.recv_timeout(WAIT).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    }

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct FinishOnDrop(Weak<Completion>);

    // `Waker::noop()` cannot stand in: this waker's Drop is what the test exercises.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for FinishOnDrop {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for FinishOnDrop {
        fn drop(&mut self) {
            let completion = self.0.upgrade().unwrap();
            assert!(completion.state.try_lock().is_some(), "drop outside gate");
            completion.finish(Ok(()));
        }
    }

    #[test]
    fn replaced_stdio_waiter_may_complete_the_operation_reentrantly() {
        let completion = Arc::new(Completion::default());
        let original = Waker::from(Arc::new(FinishOnDrop(Arc::downgrade(&completion))));
        assert!(
            completion
                .poll(&Context::from_waker(&original))
                .is_pending()
        );
        drop(original);
        let calls = Arc::new(WakeCount(AtomicUsize::new(0)));
        let replacement = Waker::from(Arc::clone(&calls));
        let context = Context::from_waker(&replacement);
        assert!(completion.poll(&context).is_pending());
        assert_eq!(calls.0.load(Ordering::SeqCst), 1);
        assert!(matches!(completion.poll(&context), Poll::Ready(Ok(()))));
    }

    #[test]
    fn abandoned_stdio_waiter_does_not_keep_its_task_alive() {
        let completion = Arc::new(Completion::default());
        let task = Arc::new(WakeCount(AtomicUsize::new(0)));
        let weak = Arc::downgrade(&task);
        let waker = Waker::from(task);
        assert!(completion.poll(&Context::from_waker(&waker)).is_pending());
        drop(waker);
        let operation = InFlight::Pool(Arc::clone(&completion));
        drop(operation);
        assert!(weak.upgrade().is_none());
        completion.finish(Ok(()));
        assert!(matches!(
            completion.poll(&Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
}
