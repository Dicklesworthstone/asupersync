//! Independently parked read/write ownership over one strict replay stream.
//!
//! Completion order and per-operation validation remain authoritative. Only
//! polling order across directions is relaxed; no byte operation is skipped.

use super::{
    AsyncRead, AsyncWrite, IoGroupReplayError, IoOperation, ReadBuf, ReplayGroupIo,
    ReplayShared, wake,
};
use parking_lot::Mutex;
use std::fmt;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Wake, Waker};

/// The independently owned direction of a split replay connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDirection {
    /// Byte reads, including recorded EOF and read errors.
    Read,
    /// Scalar/vectored writes, flush, and shutdown.
    Write,
}

impl ReplayDirection {
    const fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
        }
    }

    fn of(operation: IoOperation) -> Self {
        if operation == IoOperation::Read {
            Self::Read
        } else {
            Self::Write
        }
    }
}

struct State {
    io: Option<ReplayGroupIo>,
    waiters: [Option<Arc<Waker>>; 2],
    contended: [bool; 2],
    reunited: bool,
}

struct Shared {
    group: Arc<ReplayShared>,
    index: usize,
    id: u64,
    vectored: bool,
    remaining: [AtomicUsize; 2],
    state: Mutex<State>,
    forward: Waker,
}

// The group retains only a weak reference back to the halves. No waiter cycle
// can keep the replay tape alive after its last direction owner is dropped.
struct Forward(Weak<Shared>);
impl Wake for Forward {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(shared) = self.0.upgrade() {
            shared.notify();
        }
    }
}

fn retire(waiter: Option<Arc<Waker>>) {
    // Match the group's panic-contained callback policy, but do not spuriously
    // wake a completed, replaced, or dropped waiter merely to retire it.
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waiter))) {
        std::mem::forget(payload);
    }
}

fn notify(waiters: [Option<Arc<Waker>>; 2]) {
    for waiter in waiters.into_iter().flatten() {
        wake(waiter);
    }
}

impl Shared {
    fn notify(&self) {
        let waiters = {
            let mut state = self.state.lock();
            [state.waiters[0].take(), state.waiters[1].take()]
        };
        notify(waiters);
    }

    // Registration and turn checking use the same group lock as advance/fail.
    // Unlike the unsplit interface, the opposite direction parks instead of
    // being treated as an operation mismatch. Within the write direction the
    // original exact Write/WriteVectored/Flush/Shutdown checks still apply.
    fn enter(&self, direction: ReplayDirection) -> Result<bool, IoGroupReplayError> {
        let incoming = Arc::new(self.forward.clone());
        let (result, stale) = {
            let mut group = self.group.state.lock();
            let result = if let Some(error) = group.failure {
                Err(error)
            } else if self.remaining[direction.index()].load(Ordering::Acquire) == 0 {
                Err(IoGroupReplayError::ExhaustedHalf {
                    stream: self.id,
                    direction,
                })
            } else if let Some(next) = group.order.get(group.index) {
                Ok(next.stream == self.index && ReplayDirection::of(next.operation) == direction)
            } else {
                Err(IoGroupReplayError::Coverage(self.id))
            };
            let stale = if matches!(result, Ok(false)) {
                group.slots[self.index].waiter.replace(incoming)
            } else {
                None
            };
            (result, stale)
        };
        retire(stale);
        result
    }

    fn poll_with<O>(
        self: &Arc<Self>,
        direction: ReplayDirection,
        cx: &mut Context<'_>,
        poll: impl FnOnce(&mut ReplayGroupIo, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        // Waker::clone is arbitrary caller code. It runs before either lock.
        let incoming = Arc::new(cx.waker().clone());
        let slot = direction.index();
        let (io, stale) = {
            let mut state = self.state.lock();
            let stale = state.waiters[slot].replace(incoming);
            let io = state.io.take();
            if io.is_none() {
                state.contended[slot] = true;
            }
            (io, stale)
        };
        retire(stale);
        let Some(io) = io else {
            return Poll::Pending;
        };
        let mut lease = Lease { shared: self, io: Some(io), slot, ready: false };
        let result = match self.enter(direction) {
            Ok(false) => Poll::Pending,
            Err(error) => {
                let error = self.group.fail(error);
                self.notify();
                Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)))
            }
            Ok(true) => {
                let io = lease.io.as_mut().expect("exclusive replay lease");
                let before = io.inner.consumed_operations();
                let mut inner_cx = Context::from_waker(&self.forward);
                let result = poll(io, &mut inner_cx);
                // Captured I/O errors consume an observation too. Divergence
                // does not: the underlying component keeps its first error.
                if io.inner.consumed_operations() != before {
                    self.remaining[slot].fetch_sub(1, Ordering::AcqRel);
                }
                result
            }
        };
        lease.ready = result.is_ready();
        result
    }

    fn close(&self, direction: ReplayDirection) {
        let slot = direction.index();
        let waiter = {
            let mut state = self.state.lock();
            if state.reunited {
                return;
            }
            state.contended[slot] = false;
            state.waiters[slot].take()
        };
        retire(waiter);
        let remaining = self.remaining[slot].load(Ordering::Acquire);
        if remaining != 0 {
            self.group.fail(IoGroupReplayError::AbandonedHalf {
                stream: self.id,
                direction,
                remaining,
            });
            self.notify();
        }
    }
}

// The component is never polled while a split-state lock is held: group wakes
// can synchronously reenter the other half. Even an unwind restores ownership.
struct Lease<'a> {
    shared: &'a Shared,
    io: Option<ReplayGroupIo>,
    slot: usize,
    ready: bool,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let (retired, contenders) = {
            let mut state = self.shared.state.lock();
            debug_assert!(state.io.is_none());
            state.io = self.io.take();
            let retired = if self.ready { state.waiters[self.slot].take() } else { None };
            let contenders = std::array::from_fn(|slot| {
                if std::mem::take(&mut state.contended[slot]) {
                    state.waiters[slot].take()
                } else {
                    None
                }
            });
            (retired, contenders)
        };
        retire(retired);
        notify(contenders);
    }
}

/// Owned read direction of one captured connection; not cloneable.
/// Dropping it with unread observations invalidates the whole replay group.
pub struct ReplayGroupReadHalf { shared: Arc<Shared> }

/// Owned write/flush/shutdown direction of one captured connection; not cloneable.
/// Dropping it with unwritten observations invalidates the whole replay group.
pub struct ReplayGroupWriteHalf { shared: Arc<Shared> }

impl fmt::Debug for ReplayGroupReadHalf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayGroupReadHalf").field("stream", &self.shared.id).finish_non_exhaustive()
    }
}
impl fmt::Debug for ReplayGroupWriteHalf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayGroupWriteHalf").field("stream", &self.shared.id).finish_non_exhaustive()
    }
}

impl ReplayGroupIo {
    /// Split an offline connection into independently polled, owned directions.
    ///
    /// An early read waits for a preceding write (and conversely) without
    /// changing the captured completion order. Each direction retains exact
    /// operation, buffer-shape, and write-fingerprint validation. Recorded EOF,
    /// errors, flushes, and shutdowns must still be consumed; neither a dropped
    /// direction nor a cancelled individual polling future fabricates them.
    ///
    /// Keep each half across cancellation of individual I/O futures. Dropping
    /// a half with remaining observations poisons the group and wakes peers;
    /// dropping an exhausted half does not prevent its peer from finishing.
    /// An extra operation on an exhausted direction fails immediately, even
    /// when the other direction or another connection still has work.
    ///
    /// This allocates constant-size coordination state and scans the remaining
    /// group order once. It does not copy tape payloads, open a provider, spawn
    /// tasks, or alter any artifact bytes. The halves may move to separate
    /// tasks/threads. Call the group's `verify_complete` after draining both.
    #[must_use]
    pub fn into_split(self) -> (ReplayGroupReadHalf, ReplayGroupWriteHalf) {
        let (remaining, stale) = {
            let mut group = self.shared.state.lock();
            let mut remaining = [0usize; 2];
            for entry in &group.order[group.index..] {
                if entry.stream == self.index {
                    remaining[ReplayDirection::of(entry.operation).index()] += 1;
                }
            }
            let stale = group.slots[self.index].waiter.take();
            (remaining, stale)
        };
        retire(stale);
        let shared = Arc::new_cyclic(|weak| Shared {
            group: Arc::clone(&self.shared),
            index: self.index,
            id: self.id,
            vectored: self.is_write_vectored(),
            remaining: remaining.map(AtomicUsize::new),
            state: Mutex::new(State {
                io: Some(self),
                waiters: [None, None],
                contended: [false, false],
                reunited: false,
            }),
            forward: Waker::from(Arc::new(Forward(Weak::clone(weak)))),
        });
        (ReplayGroupReadHalf { shared: Arc::clone(&shared) }, ReplayGroupWriteHalf { shared })
    }
}

impl ReplayGroupReadHalf {
    /// Whether these halves came from the same call to `into_split`.
    ///
    /// Stream IDs alone are insufficient: separate groups may reuse an ID.
    #[must_use]
    pub fn is_pair_of(&self, write: &ReplayGroupWriteHalf) -> bool {
        Arc::ptr_eq(&self.shared, &write.shared)
    }

    /// Recover the original strict replay stream at its current tape position.
    ///
    /// This transfers ownership, not observations: no read, write, EOF, flush,
    /// or shutdown is synthesized, and an existing divergence remains sticky.
    /// The stream can be split again or driven through its strict unsplit API.
    /// Callers must first recover both owned halves from their tasks; owning
    /// both excludes any in-flight borrowed I/O operation or component lease.
    ///
    /// Pending-operation waiters left after cancellation are detached and
    /// retired outside both locks. Callbacks already dispatched concurrently
    /// may still run; reunification cannot revoke an in-flight callback.
    ///
    /// # Errors
    /// Halves from different splits are returned unchanged as `(read, write)`.
    /// Neither group is poisoned and no waiter or observation is consumed.
    pub fn reunite(
        self,
        write: ReplayGroupWriteHalf,
    ) -> Result<ReplayGroupIo, (Self, ReplayGroupWriteHalf)> {
        if !self.is_pair_of(&write) {
            return Err((self, write));
        }
        let (io, waiters) = {
            let mut state = self.shared.state.lock();
            let io = state.io.take().expect("both half owners exclude an active lease");
            state.reunited = true;
            state.contended = [false, false];
            let waiters = [state.waiters[0].take(), state.waiters[1].take()];
            (io, waiters)
        };
        let forward = self.shared.group.state.lock().slots[self.shared.index].waiter.take();
        retire(forward);
        for waiter in waiters {
            retire(waiter);
        }
        // The reunited flag prevents either consumed half's Drop from
        // misclassifying the returned provider's remaining work as abandoned.
        drop(self);
        drop(write);
        Ok(io)
    }
}

impl AsyncRead for ReplayGroupReadHalf {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.shared.poll_with(ReplayDirection::Read, cx, |io, cx| Pin::new(io).poll_read(cx, buf))
    }
}
impl AsyncWrite for ReplayGroupWriteHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.shared.poll_with(ReplayDirection::Write, cx, |io, cx| Pin::new(io).poll_write(cx, buf))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.shared.poll_with(ReplayDirection::Write, cx, |io, cx| Pin::new(io).poll_write_vectored(cx, bufs))
    }
    fn is_write_vectored(&self) -> bool { self.shared.vectored }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.poll_with(ReplayDirection::Write, cx, |io, cx| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.poll_with(ReplayDirection::Write, cx, |io, cx| Pin::new(io).poll_shutdown(cx))
    }
}
impl Drop for ReplayGroupReadHalf {
    fn drop(&mut self) { self.shared.close(ReplayDirection::Read); }
}
impl Drop for ReplayGroupWriteHalf {
    fn drop(&mut self) { self.shared.close(ReplayDirection::Write); }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod ownership_tests;
