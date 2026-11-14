//! Caller-owned forwarding from a native stream into a native sink.
//!
//! Follow-up to br-asupersync-1alzu and br-asupersync-2ds93: compose the native
//! Stream/Sink protocols without putting extracted items in a disposable wait.

use super::{Sink, Stream};
use crate::cx::{CancelWakerToken, Cx};
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// Maximum successful admissions before yielding to the executor.
const SENDS_PER_POLL: usize = 64;

/// Provider operation at which a forwarding session stopped permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkForwardStage {
    /// Polling the source; only a provider panic can fail this operation.
    Source,
    /// Waiting for the sink to accept another item.
    Ready,
    /// Transferring ownership of an item to the sink.
    Send,
    /// Flushing accepted items.
    Flush,
    /// Closing the sink after source EOF and a successful flush.
    Close,
}

/// Why one invocation of [`SinkForwardSession::run`] stopped.
#[derive(Debug)]
pub enum SinkForwardError<E> {
    /// The context checkpoint requested cancellation. The session can resume
    /// under an active context, retaining its source, sink and staged item.
    Cancelled(crate::Error),
    /// A sink operation failed. The session is fenced against further polling.
    /// A `Send` failure has already transferred the item to `start_send`; the
    /// generic Sink contract does not return it or promise rollback.
    Sink {
        /// Operation that failed.
        stage: SinkForwardStage,
        /// Error returned by the sink.
        error: E,
    },
    /// An earlier sink error or provider panic fenced this session. Extract
    /// its parts to make an application-specific recovery decision.
    Failed {
        /// Operation whose result is failed or uncertain.
        stage: SinkForwardStage,
    },
}

impl<E: std::fmt::Display> std::fmt::Display for SinkForwardError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled(error) => write!(f, "sink forwarding cancelled: {error}"),
            Self::Sink { stage, error } => {
                write!(f, "sink forwarding failed during {stage:?}: {error}")
            }
            Self::Failed { stage } => {
                write!(f, "sink forwarding is fenced after {stage:?}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SinkForwardError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cancelled(error) => Some(error),
            Self::Sink { error, .. } => Some(error),
            Self::Failed { .. } => None,
        }
    }
}

/// Cumulative forwarding progress, independent of any one borrowing run future.
///
/// Counts saturate at `u64::MAX`. They describe successful Sink operations,
/// not delivery, persistence, or consumer processing. A failed or panicking
/// operation can have additional effects that these counters cannot measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkForwardProgress {
    /// Items for which `start_send` returned success.
    pub accepted_items: u64,
    /// Accepted items covered by the most recent successful `poll_flush`.
    pub flushed_items: u64,
    /// One extracted item is still owned by the session, awaiting admission.
    pub has_pending: bool,
    /// Source EOF was observed and will never be polled again.
    pub source_exhausted: bool,
    /// EOF, flush and sink close all completed successfully.
    pub complete: bool,
    /// A sink error or provider panic prevents further automatic progress.
    pub failed: Option<SinkForwardStage>,
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Forward,
    Flush,
    Close,
    Complete,
    Failed(SinkForwardStage),
}

/// Retains a source, a destination and at most one extracted item across waits.
///
/// [`run`](Self::run) borrows this session. Dropping that future, or returning
/// on explicit context cancellation, leaves the transfer state here so another
/// run can resume it. No background task, cloned item, or unbounded intermediate
/// queue is used. The source and sink retain responsibility for their own
/// buffers and for side effects performed inside a pending poll. Resuming does
/// not override a provider's own terminal or cancellation state.
///
/// Backpressure is checked before transferring each staged item. If the source
/// becomes pending, accepted items are flushed so a partially filled framed
/// buffer cannot stall an interactive pipeline. Source EOF is latched, then the
/// sink is flushed and closed. Success therefore finishes the sending side;
/// use a separate session for a separate stream of messages. Running an already
/// completed session returns its existing progress without polling providers.
///
/// Sink errors are terminal for the session. In particular, a failed
/// `start_send` has consumed the staged value and may have changed the sink.
/// Provider panics also fence further runs if an application catches the unwind.
/// [`into_parts`](Self::into_parts) returns the remaining state without claiming
/// that retrying the failed operation would be safe. Dropping the session itself
/// can discard its retained data; it does not asynchronously flush or close.
///
/// The polling methods require `S` and `K` to be `Unpin`; pass `Pin<Box<_>>` or
/// `Pin<&mut _>` to use pinned `!Unpin` providers through their forwarding impls.
/// Items have no `Unpin`, `Clone`, `Send`, or `'static` bound. A source yielding
/// `Result<T, E>` forwards those values as ordinary items; it is not implicitly
/// unwrapped or treated as a separate error channel.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx, writer: asupersync::io::DuplexStream) {
/// use asupersync::codec::{FramedWrite, LinesCodec};
/// use asupersync::stream::{SinkForwardSession, iter};
/// let source = iter(["first".to_owned(), "second".to_owned()]);
/// let mut transfer = SinkForwardSession::new(source, FramedWrite::new(writer, LinesCodec::new()));
/// let progress = transfer.run(cx).await.expect("forward and finish");
/// assert_eq!(progress.accepted_items, 2);
/// assert!(progress.complete);
/// # }
/// ```
pub struct SinkForwardSession<S: Stream, K> {
    source: S,
    sink: K,
    pending: Option<S::Item>,
    phase: Phase,
    source_exhausted: bool,
    needs_flush: bool,
    accepted_items: u64,
    flushed_items: u64,
}

impl<S: Stream, K> SinkForwardSession<S, K> {
    /// Creates a transfer with no staged item. Construction performs no I/O.
    #[must_use]
    pub fn new(source: S, sink: K) -> Self {
        Self {
            source,
            sink,
            pending: None,
            phase: Phase::Forward,
            source_exhausted: false,
            needs_flush: false,
            accepted_items: 0,
            flushed_items: 0,
        }
    }

    /// Returns cumulative progress without polling either provider.
    #[must_use]
    pub fn progress(&self) -> SinkForwardProgress {
        SinkForwardProgress {
            accepted_items: self.accepted_items,
            flushed_items: self.flushed_items,
            has_pending: self.pending.is_some(),
            source_exhausted: self.source_exhausted,
            complete: matches!(self.phase, Phase::Complete),
            failed: match self.phase {
                Phase::Failed(stage) => Some(stage),
                _ => None,
            },
        }
    }

    /// Borrows the retained source and sink for inspection.
    #[must_use]
    pub fn get_ref(&self) -> (&S, &K) {
        (&self.source, &self.sink)
    }

    /// Returns the source, sink and any item not yet passed to `start_send`.
    ///
    /// Inspect [`progress`](Self::progress) first if recovery needs the stage
    /// or counts. Accepted items stay inside the concrete sink, if it retains
    /// them. A failed `start_send` item cannot be recovered by this adapter.
    #[must_use]
    pub fn into_parts(self) -> (S, K, Option<S::Item>) {
        (self.source, self.sink, self.pending)
    }
}

impl<S, K> SinkForwardSession<S, K>
where
    S: Stream + Unpin,
    K: Sink<S::Item> + Unpin,
{
    /// Drives the transfer through EOF, flush and close, or until it stops.
    ///
    /// Checkpoints honor cancellation masks. Cancellation wakes an idle-source
    /// or blocked-sink wait, and removes only this run's wake registration on
    /// completion or drop. Resume with an active context after cancellation.
    /// A source or sink retaining a task waker may keep that separate wake alive.
    /// Always-ready pipelines yield after a bounded number of admissions.
    pub async fn run<Caps>(
        &mut self,
        cx: &Cx<Caps>,
    ) -> Result<SinkForwardProgress, SinkForwardError<K::Error>> {
        let mut cancellation = ForwardCancellation {
            cx,
            registration: None,
        };
        poll_fn(|task| match self.poll_run(cx, task) {
            Poll::Ready(result) => {
                cancellation.clear();
                Poll::Ready(result)
            }
            Poll::Pending => {
                cancellation.refresh(task.waker());
                // Cancellation can race provider polling or registration.
                if cx.is_cancel_requested() {
                    if let Err(error) = cx.checkpoint() {
                        cancellation.clear();
                        return Poll::Ready(Err(SinkForwardError::Cancelled(error)));
                    }
                }
                Poll::Pending
            }
        })
        .await
    }

    fn poll_run<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        task: &mut Context<'_>,
    ) -> Poll<Result<SinkForwardProgress, SinkForwardError<K::Error>>> {
        let mut sent = 0usize;
        // A new poll must refresh the source's task waker after resuming a
        // flush. Only a Pending observed in THIS poll can safely park us.
        let mut source_pending = false;
        loop {
            match self.phase {
                Phase::Complete => return Poll::Ready(Ok(self.progress())),
                Phase::Failed(stage) => {
                    return Poll::Ready(Err(SinkForwardError::Failed { stage }));
                }
                _ => {}
            }
            if let Err(error) = cx.checkpoint() {
                return Poll::Ready(Err(SinkForwardError::Cancelled(error)));
            }

            match self.phase {
                Phase::Forward if self.pending.is_none() => {
                    // Fence before invoking provider code. A panic may follow
                    // side effects, so only normal returns permit another run.
                    self.phase = Phase::Failed(SinkForwardStage::Source);
                    match Pin::new(&mut self.source).poll_next(task) {
                        Poll::Ready(Some(item)) => {
                            self.pending = Some(item);
                            self.phase = Phase::Forward;
                        }
                        Poll::Ready(None) => {
                            self.source_exhausted = true;
                            self.phase = Phase::Flush;
                        }
                        Poll::Pending => {
                            self.phase = Phase::Forward;
                            if !self.needs_flush {
                                return Poll::Pending;
                            }
                            source_pending = true;
                            self.phase = Phase::Flush;
                        }
                    }
                }
                Phase::Forward => {
                    self.phase = Phase::Failed(SinkForwardStage::Ready);
                    match Pin::new(&mut self.sink).poll_ready(task) {
                        Poll::Pending => {
                            self.phase = Phase::Forward;
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(SinkForwardError::Sink {
                                stage: SinkForwardStage::Ready,
                                error,
                            }));
                        }
                        Poll::Ready(Ok(())) => self.phase = Phase::Forward,
                    }
                    // Readiness itself may publish cancellation. Keep the item
                    // until the final checkpoint before transferring ownership.
                    if let Err(error) = cx.checkpoint() {
                        return Poll::Ready(Err(SinkForwardError::Cancelled(error)));
                    }
                    self.phase = Phase::Failed(SinkForwardStage::Send);
                    let item = self.pending.take().expect("staged item precedes admission");
                    if let Err(error) = Pin::new(&mut self.sink).start_send(item) {
                        return Poll::Ready(Err(SinkForwardError::Sink {
                            stage: SinkForwardStage::Send,
                            error,
                        }));
                    }
                    self.accepted_items = self.accepted_items.saturating_add(1);
                    self.needs_flush = true;
                    self.phase = Phase::Forward;
                    sent += 1;
                    if sent >= SENDS_PER_POLL {
                        task.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Phase::Flush => {
                    self.phase = Phase::Failed(SinkForwardStage::Flush);
                    match Pin::new(&mut self.sink).poll_flush(task) {
                        Poll::Pending => {
                            self.phase = Phase::Flush;
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(SinkForwardError::Sink {
                                stage: SinkForwardStage::Flush,
                                error,
                            }));
                        }
                        Poll::Ready(Ok(())) => {
                            self.flushed_items = self.accepted_items;
                            self.needs_flush = false;
                            self.phase = if self.source_exhausted {
                                Phase::Close
                            } else {
                                Phase::Forward
                            };
                            if source_pending {
                                return Poll::Pending;
                            }
                        }
                    }
                }
                Phase::Close => {
                    self.phase = Phase::Failed(SinkForwardStage::Close);
                    match Pin::new(&mut self.sink).poll_close(task) {
                        Poll::Pending => {
                            self.phase = Phase::Close;
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(SinkForwardError::Sink {
                                stage: SinkForwardStage::Close,
                                error,
                            }));
                        }
                        Poll::Ready(Ok(())) => {
                            self.phase = Phase::Complete;
                            return Poll::Ready(Ok(self.progress()));
                        }
                    }
                }
                Phase::Complete | Phase::Failed(_) => unreachable!("handled before checkpoint"),
            }
        }
    }
}

struct ForwardRegistration {
    waker: Waker,
    token: CancelWakerToken,
}

struct ForwardCancellation<'a, Caps> {
    cx: &'a Cx<Caps>,
    registration: Option<ForwardRegistration>,
}

impl<Caps> ForwardCancellation<'_, Caps> {
    fn refresh(&mut self, waker: &Waker) {
        let unchanged = self
            .registration
            .as_ref()
            .is_some_and(|entry| entry.waker.will_wake(waker));
        let incoming = if unchanged { None } else { Some(waker.clone()) };
        let previous = self.registration.as_ref().map(|entry| entry.token);
        let token = self.cx.refresh_cancel_waker(previous, waker);
        let retired = if let Some(waker) = incoming {
            self.registration
                .replace(ForwardRegistration { waker, token })
        } else {
            self.registration
                .as_mut()
                .expect("unchanged waker retains its cancellation registration")
                .token = token;
            None
        };
        drop(retired);
    }

    fn clear(&mut self) {
        if let Some(registered) = self.registration.take() {
            self.cx.clear_cancel_waker(registered.token);
            drop(registered);
        }
    }
}

impl<Caps> Drop for ForwardCancellation<'_, Caps> {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
#[path = "sink_forward_tests.rs"]
mod tests;
